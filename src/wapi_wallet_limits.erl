-module(wapi_wallet_limits).
%
% IMPORTANT: calculation is approximate and does NOT cover some cases:
% - selectors {decisions, _} for terminals are not handled
% - exclusive bounds are treated as inclusive (strictness lost)
% - gaps in intervals are not preserved when merging
% - terminals with withdrawal cash_limit=decisions are ignored (no provider fallback)
% - candidate terminals with allowed=false are ignored
%

-include_lib("damsel/include/dmsl_domain_thrift.hrl").
-include_lib("damsel/include/dmsl_payproc_thrift.hrl").

-export([get_wallet_limits/3]).

-type handler_context() :: wapi_handler_utils:handler_context().

-spec get_wallet_limits(binary(), binary(), handler_context()) -> {ok, [map()]} | {error, {wallet, notfound}}.
get_wallet_limits(PartyID, WalletID, Context) ->
    case get_wallet_config(PartyID, WalletID) of
        {error, notfound} ->
            {error, {wallet, notfound}};
        {ok, WalletConfig} ->
            Currency = WalletConfig#domain_WalletConfig.account#domain_WalletAccount.currency,
            Revision = wapi_domain_backend:head(),
            WalletTerms = get_wallet_terms(WalletConfig#domain_WalletConfig.terms, Revision),
            Methods = extract_withdrawal_methods(WalletTerms),
            WithdrawalLimit = extract_withdrawal_limit(WalletTerms, Currency),
            TerminalRefs = get_withdrawal_terminal_refs(
                WalletConfig#domain_WalletConfig.payment_institution,
                PartyID,
                WalletID,
                Revision,
                Context
            ),
            TermLimit = aggregate_terminal_limits(TerminalRefs, Currency, Revision),
            EffectiveLimit = intersect_optional(WithdrawalLimit, TermLimit),
            Limits = lists:flatmap(
                fun(Method) ->
                    encode_limits(Currency, Method, EffectiveLimit)
                end,
                Methods
            ),
            {ok, Limits}
    end.

get_wallet_config(PartyID, WalletID) ->
    ObjectRef = {wallet_config, #domain_WalletConfigRef{id = WalletID}},
    case wapi_domain_backend:get_object(ObjectRef) of
        {ok, #domain_WalletConfig{party_ref = #domain_PartyConfigRef{id = PartyID}} = WalletConfig} ->
            {ok, WalletConfig};
        _ ->
            {error, notfound}
    end.

get_wallet_terms(TermsRef, Revision) ->
    case wapi_domain_backend:get_object(Revision, {term_set_hierarchy, TermsRef}) of
        {ok, #domain_TermSetHierarchy{term_set = TermSet}} ->
            TermSet;
        _ ->
            undefined
    end.

extract_withdrawal_methods(#domain_TermSet{
    wallets = #domain_WalletServiceTerms{
        withdrawals = #domain_WithdrawalServiceTerms{methods = {value, MethodRefs}}
    }
}) ->
    Methods = [normalize_withdrawal_method(Type) || #domain_PaymentMethodRef{id = {Type, _ID}} <- MethodRefs],
    lists:usort(Methods);
extract_withdrawal_methods(_) ->
    [].

extract_withdrawal_limit(undefined, _Currency) ->
    undefined;
extract_withdrawal_limit(#domain_TermSet{wallets = undefined}, _Currency) ->
    undefined;
extract_withdrawal_limit(#domain_TermSet{wallets = Wallets}, Currency) ->
    case Wallets#domain_WalletServiceTerms.withdrawals of
        undefined ->
            undefined;
        #domain_WithdrawalServiceTerms{cash_limit = CashLimitSelector} ->
            range_from_selector(CashLimitSelector, Currency)
    end.

get_withdrawal_terminal_refs(PiRef, PartyID, WalletID, Revision, Context) ->
    case wapi_domain_backend:get_object(Revision, {payment_institution, PiRef}) of
        {ok, #domain_PaymentInstitution{withdrawal_routing_rules = RulesetRef}} ->
            case compute_routing_ruleset(RulesetRef, PartyID, WalletID, Revision, Context) of
                {ok, #domain_RoutingRuleset{decisions = {candidates, Candidates}}} ->
                    AllowedCandidates = [
                        C#domain_RoutingCandidate.terminal
                     || C <- Candidates,
                        predicate_allowed(C#domain_RoutingCandidate.allowed)
                    ],
                    lists:usort(AllowedCandidates);
                _ ->
                    []
            end;
        _ ->
            []
    end.

compute_routing_ruleset(undefined, _PartyID, _WalletID, _Revision, _Context) ->
    undefined;
compute_routing_ruleset(
    #domain_RoutingRules{policies = RulesetRef},
    PartyID,
    WalletID,
    Revision,
    Context
) ->
    Varset = #payproc_Varset{
        party_ref = #domain_PartyConfigRef{id = PartyID},
        wallet_id = WalletID
    },
    case
        wapi_handler_utils:service_call(
            {party_management, 'ComputeRoutingRuleset', {RulesetRef, Revision, Varset}},
            Context
        )
    of
        {ok, #domain_RoutingRuleset{} = Ruleset} ->
            {ok, Ruleset};
        _ ->
            undefined
    end.

aggregate_terminal_limits([], _Currency, _Revision) ->
    undefined;
aggregate_terminal_limits([TerminalRef | TerminalRefs], Currency, Revision) ->
    Limit0 = get_terminal_limit(TerminalRef, Currency, Revision),
    log_terminal_terms(TerminalRef, Limit0),
    lists:foldl(
        fun(TerminalRef1, LimitAcc) ->
            Limit = get_terminal_limit(TerminalRef1, Currency, Revision),
            log_terminal_terms(TerminalRef1, Limit),
            union_optional(LimitAcc, Limit)
        end,
        Limit0,
        TerminalRefs
    ).

log_terminal_terms(TerminalRef, Limit) ->
    logger:debug(
        "Wallet cash limits for terminal ~p: limit=~p",
        [TerminalRef, Limit]
    ).

get_terminal_limit(TerminalRef, Currency, Revision) ->
    case wapi_domain_backend:get_object(Revision, {terminal, TerminalRef}) of
        {ok, #domain_Terminal{provider_ref = ProviderRef, terms = TerminalTerms}} ->
            ProviderTerms = get_provider_terms(ProviderRef, Revision),
            compute_terminal_limit(TerminalTerms, ProviderTerms, Currency);
        _ ->
            undefined
    end.

compute_terminal_limit(TerminalTerms, ProviderTerms, Currency) ->
    TerminalWithdrawalTerms = extract_withdrawal_terms(TerminalTerms),
    case terminal_and_provider_allowed(TerminalWithdrawalTerms, ProviderTerms) of
        true ->
            case extract_provider_limit(TerminalTerms, Currency) of
                undefined ->
                    extract_provider_limit(ProviderTerms, Currency);
                TerminalLimit ->
                    TerminalLimit
            end;
        false ->
            undefined
    end.

extract_withdrawal_terms(#domain_ProvisionTermSet{
    wallet = #domain_WalletProvisionTerms{withdrawals = WithdrawalTerms}
}) ->
    WithdrawalTerms;
extract_withdrawal_terms(_) ->
    undefined.

predicate_allowed({constant, false}) ->
    false;
predicate_allowed({all_of, List}) when is_list(List) ->
    lists:all(fun predicate_allowed/1, List);
predicate_allowed(_) ->
    true.

terminal_and_provider_allowed(undefined, ProviderTerms) ->
    provider_withdrawal_allowed(ProviderTerms);
terminal_and_provider_allowed(#domain_WithdrawalProvisionTerms{} = TerminalTerms, ProviderTerms) ->
    TerminalAllowed = predicate_allowed(TerminalTerms#domain_WithdrawalProvisionTerms.allow),
    TerminalGlobalAllowed = predicate_allowed(TerminalTerms#domain_WithdrawalProvisionTerms.global_allow),
    TerminalAllowed andalso TerminalGlobalAllowed andalso provider_withdrawal_allowed(ProviderTerms).

provider_withdrawal_allowed(undefined) ->
    true;
provider_withdrawal_allowed(#domain_ProvisionTermSet{
    wallet = #domain_WalletProvisionTerms{
        withdrawals = #domain_WithdrawalProvisionTerms{} = ProviderWithdrawalTerms
    }
}) ->
    predicate_allowed(ProviderWithdrawalTerms#domain_WithdrawalProvisionTerms.allow) andalso
        predicate_allowed(ProviderWithdrawalTerms#domain_WithdrawalProvisionTerms.global_allow);
provider_withdrawal_allowed(_) ->
    true.

get_provider_terms(ProviderRef, Revision) ->
    case wapi_domain_backend:get_object(Revision, {provider, ProviderRef}) of
        {ok, #domain_Provider{terms = Terms}} ->
            Terms;
        _ ->
            undefined
    end.

extract_provider_limit(undefined, _Currency) ->
    undefined;
extract_provider_limit(#domain_ProvisionTermSet{wallet = undefined}, _Currency) ->
    undefined;
extract_provider_limit(#domain_ProvisionTermSet{wallet = WalletTerms}, Currency) ->
    case WalletTerms#domain_WalletProvisionTerms.withdrawals of
        undefined ->
            undefined;
        #domain_WithdrawalProvisionTerms{cash_limit = CashLimitSelector} ->
            range_from_selector(CashLimitSelector, Currency)
    end.

range_from_selector({value, #domain_CashRange{} = Range}, Currency) ->
    normalize_range(Range, Currency);
range_from_selector(_, _Currency) ->
    undefined.

normalize_range(#domain_CashRange{lower = Lower, upper = Upper}, #domain_CurrencyRef{symbolic_code = CurrencyCode}) ->
    {LowerAmount, LowerCode} = extract_bound(Lower),
    {UpperAmount, UpperCode} = extract_bound(Upper),
    case {LowerCode, UpperCode} of
        {CurrencyCode, CurrencyCode} ->
            #{
                currency => CurrencyCode,
                lower => LowerAmount,
                upper => UpperAmount
            };
        _ ->
            undefined
    end.

extract_bound({inclusive, #domain_Cash{amount = Amount, currency = #domain_CurrencyRef{symbolic_code = Code}}}) ->
    {Amount, Code};
extract_bound({exclusive, #domain_Cash{amount = Amount, currency = #domain_CurrencyRef{symbolic_code = Code}}}) ->
    {Amount, Code}.

intersect_optional(undefined, Range) ->
    Range;
intersect_optional(Range, undefined) ->
    Range;
intersect_optional(#{currency := Currency} = R1, #{currency := Currency} = R2) ->
    intersect_ranges(R1, R2).

intersect_ranges(#{lower := Lower1, upper := Upper1} = R1, #{lower := Lower2, upper := Upper2}) ->
    Lower = max(Lower1, Lower2),
    Upper = min(Upper1, Upper2),
    case valid_range(Lower, Upper) of
        true ->
            R1#{lower => Lower, upper => Upper};
        false ->
            undefined
    end.

union_optional(undefined, Range) ->
    Range;
union_optional(Range, undefined) ->
    Range;
union_optional(#{currency := Currency} = R1, #{currency := Currency} = R2) ->
    union_ranges(R1, R2).

union_ranges(#{lower := Lower1, upper := Upper1} = R1, #{lower := Lower2, upper := Upper2}) ->
    Lower = min(Lower1, Lower2),
    Upper = max(Upper1, Upper2),
    R1#{lower => Lower, upper => Upper}.

valid_range(LowerAmount, UpperAmount) when LowerAmount =< UpperAmount ->
    true;
valid_range(_, _) ->
    false.

encode_limits(_Currency, _Method, undefined) ->
    [];
encode_limits(_Currency, Method, #{currency := CurrencyCode} = Range) ->
    Encoded = encode_range(CurrencyCode, Range),
    [Encoded#{<<"withdrawalMethod">> => encode_withdrawal_method(Method)}].

encode_range(CurrencyCode, #{lower := Lower, upper := Upper}) ->
    #{
        <<"currency">> => CurrencyCode,
        <<"lowerBound">> => encode_bound(Lower),
        <<"upperBound">> => encode_bound(Upper)
    }.

encode_bound(Amount) ->
    #{
        <<"amount">> => Amount,
        <<"inclusive">> => true
    }.

normalize_withdrawal_method(bank_card) ->
    bank_card;
normalize_withdrawal_method(digital_wallet) ->
    digital_wallet;
normalize_withdrawal_method(_) ->
    generic.

encode_withdrawal_method(bank_card) ->
    #{
        <<"method">> => <<"WithdrawalMethodBankCard">>,
        <<"paymentSystems">> => []
    };
encode_withdrawal_method(digital_wallet) ->
    #{
        <<"method">> => <<"WithdrawalMethodDigitalWallet">>,
        <<"providers">> => []
    };
encode_withdrawal_method(generic) ->
    #{
        <<"method">> => <<"WithdrawalMethodGeneric">>,
        <<"providers">> => []
    }.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-spec predicate_allowed_undefined_test() -> _.
predicate_allowed_undefined_test() ->
    ?assertEqual(true, predicate_allowed(undefined)).

-spec predicate_allowed_constant_true_test() -> _.
predicate_allowed_constant_true_test() ->
    ?assertEqual(true, predicate_allowed({constant, true})).

-spec predicate_allowed_constant_false_test() -> _.
predicate_allowed_constant_false_test() ->
    ?assertEqual(false, predicate_allowed({constant, false})).

-spec predicate_allowed_other_predicates_test() -> _.
predicate_allowed_other_predicates_test() ->
    ?assertEqual(true, predicate_allowed({all_of, []})),
    ?assertEqual(true, predicate_allowed({all_of, [{constant, true}, {constant, true}]})),
    ?assertEqual(false, predicate_allowed({all_of, [{constant, true}, {constant, false}]})),
    ?assertEqual(false, predicate_allowed({all_of, [{all_of, [{constant, true}, {constant, false}]}]})),
    ?assertEqual(true, predicate_allowed({any_of, []})),
    ?assertEqual(true, predicate_allowed({condition, []})).

-spec terminal_and_provider_allowed_all_true_test() -> _.
terminal_and_provider_allowed_all_true_test() ->
    TerminalTerms = #domain_WithdrawalProvisionTerms{
        allow = {constant, true},
        global_allow = {constant, true}
    },
    ProviderTerms = #domain_ProvisionTermSet{
        wallet = #domain_WalletProvisionTerms{
            withdrawals = #domain_WithdrawalProvisionTerms{
                allow = {constant, true},
                global_allow = {constant, true}
            }
        }
    },
    ?assertEqual(true, terminal_and_provider_allowed(TerminalTerms, ProviderTerms)).

-spec terminal_and_provider_allowed_terminal_allow_false_test() -> _.
terminal_and_provider_allowed_terminal_allow_false_test() ->
    TerminalTerms = #domain_WithdrawalProvisionTerms{
        allow = {constant, false},
        global_allow = {constant, true}
    },
    ProviderTerms = #domain_ProvisionTermSet{
        wallet = #domain_WalletProvisionTerms{
            withdrawals = #domain_WithdrawalProvisionTerms{
                allow = {constant, true},
                global_allow = {constant, true}
            }
        }
    },
    ?assertEqual(false, terminal_and_provider_allowed(TerminalTerms, ProviderTerms)).

-spec terminal_and_provider_allowed_provider_global_allow_false_test() -> _.
terminal_and_provider_allowed_provider_global_allow_false_test() ->
    TerminalTerms = #domain_WithdrawalProvisionTerms{
        allow = {constant, true},
        global_allow = {constant, true}
    },
    ProviderTerms = #domain_ProvisionTermSet{
        wallet = #domain_WalletProvisionTerms{
            withdrawals = #domain_WithdrawalProvisionTerms{
                allow = {constant, true},
                global_allow = {constant, false}
            }
        }
    },
    ?assertEqual(false, terminal_and_provider_allowed(TerminalTerms, ProviderTerms)).

-spec terminal_and_provider_allowed_provider_allow_false_test() -> _.
terminal_and_provider_allowed_provider_allow_false_test() ->
    TerminalTerms = #domain_WithdrawalProvisionTerms{
        allow = {constant, true},
        global_allow = {constant, true}
    },
    ProviderTerms = #domain_ProvisionTermSet{
        wallet = #domain_WalletProvisionTerms{
            withdrawals = #domain_WithdrawalProvisionTerms{
                allow = {constant, false},
                global_allow = {constant, true}
            }
        }
    },
    ?assertEqual(false, terminal_and_provider_allowed(TerminalTerms, ProviderTerms)).

-spec terminal_and_provider_allowed_provider_undefined_test() -> _.
terminal_and_provider_allowed_provider_undefined_test() ->
    TerminalTerms = #domain_WithdrawalProvisionTerms{
        allow = {constant, true},
        global_allow = {constant, true}
    },
    ?assertEqual(true, terminal_and_provider_allowed(TerminalTerms, undefined)).

-spec intersect_ranges_non_overlapping_test() -> _.
intersect_ranges_non_overlapping_test() ->
    R1 = #{currency => <<"RUB">>, lower => 200, upper => 400},
    R2 = #{currency => <<"RUB">>, lower => 500, upper => 800},
    ?assertEqual(undefined, intersect_ranges(R1, R2)).

-spec compute_terminal_limit_provider_disallowed_returns_undefined_test() -> _.
compute_terminal_limit_provider_disallowed_returns_undefined_test() ->
    Rub = #domain_CurrencyRef{symbolic_code = <<"RUB">>},
    TerminalLimitRange = #domain_CashRange{
        lower = {inclusive, #domain_Cash{amount = 300, currency = Rub}},
        upper = {inclusive, #domain_Cash{amount = 900, currency = Rub}}
    },
    TerminalTerms = #domain_ProvisionTermSet{
        wallet = #domain_WalletProvisionTerms{
            withdrawals = #domain_WithdrawalProvisionTerms{
                allow = {constant, true},
                global_allow = {constant, true},
                cash_limit = {value, TerminalLimitRange}
            }
        }
    },
    ProviderTerms = #domain_ProvisionTermSet{
        wallet = #domain_WalletProvisionTerms{
            withdrawals = #domain_WithdrawalProvisionTerms{
                allow = {constant, true},
                global_allow = {constant, false}
            }
        }
    },
    ?assertEqual(undefined, compute_terminal_limit(TerminalTerms, ProviderTerms, Rub)).

-spec compute_terminal_limit_allowed_returns_terminal_limit_test() -> _.
compute_terminal_limit_allowed_returns_terminal_limit_test() ->
    Rub = #domain_CurrencyRef{symbolic_code = <<"RUB">>},
    TerminalLimitRange = #domain_CashRange{
        lower = {inclusive, #domain_Cash{amount = 300, currency = Rub}},
        upper = {inclusive, #domain_Cash{amount = 900, currency = Rub}}
    },
    TerminalTerms = #domain_ProvisionTermSet{
        wallet = #domain_WalletProvisionTerms{
            withdrawals = #domain_WithdrawalProvisionTerms{
                allow = {constant, true},
                global_allow = {constant, true},
                cash_limit = {value, TerminalLimitRange}
            }
        }
    },
    ProviderTerms = #domain_ProvisionTermSet{
        wallet = #domain_WalletProvisionTerms{
            withdrawals = #domain_WithdrawalProvisionTerms{
                allow = {constant, true},
                global_allow = {constant, true}
            }
        }
    },
    ?assertEqual(
        #{currency => <<"RUB">>, lower => 300, upper => 900},
        compute_terminal_limit(TerminalTerms, ProviderTerms, Rub)
    ).

-spec compute_terminal_limit_allowed_fallback_to_provider_limit_test() -> _.
compute_terminal_limit_allowed_fallback_to_provider_limit_test() ->
    Rub = #domain_CurrencyRef{symbolic_code = <<"RUB">>},
    ProviderLimitRange = #domain_CashRange{
        lower = {inclusive, #domain_Cash{amount = 100, currency = Rub}},
        upper = {inclusive, #domain_Cash{amount = 500, currency = Rub}}
    },
    TerminalTerms = #domain_ProvisionTermSet{
        wallet = #domain_WalletProvisionTerms{
            withdrawals = #domain_WithdrawalProvisionTerms{
                allow = {constant, true},
                global_allow = {constant, true},
                cash_limit = undefined
            }
        }
    },
    ProviderTerms = #domain_ProvisionTermSet{
        wallet = #domain_WalletProvisionTerms{
            withdrawals = #domain_WithdrawalProvisionTerms{
                allow = {constant, true},
                global_allow = {constant, true},
                cash_limit = {value, ProviderLimitRange}
            }
        }
    },
    ?assertEqual(
        #{currency => <<"RUB">>, lower => 100, upper => 500},
        compute_terminal_limit(TerminalTerms, ProviderTerms, Rub)
    ).

-endif.
