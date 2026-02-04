-module(wapi_wallet_limits).
%
% IMPORTANT: calculation is approximate and does NOT cover some cases:
% - selectors {decisions, _} for terminals are not handled
% - exclusive bounds are treated as inclusive (strictness lost)
% - terminals with cash_limit=decisions are ignored (no provider fallback)
% - when methods are missing, response is empty even if limits are computed
%

-include_lib("damsel/include/dmsl_domain_thrift.hrl").

-export([get_wallet_limits/3]).

-type handler_context() :: wapi_wallet_backend:handler_context().

-spec get_wallet_limits(binary(), binary(), handler_context()) -> {ok, [map()]} | {error, {wallet, notfound}}.
get_wallet_limits(PartyID, WalletID, _Context) ->
    case get_wallet_config(PartyID, WalletID) of
        {error, notfound} ->
            {error, {wallet, notfound}};
        {ok, WalletConfig} ->
            Currency = WalletConfig#domain_WalletConfig.account#domain_WalletAccount.currency,
            Revision = wapi_domain_backend:head(),
            WalletTerms = get_wallet_terms(WalletConfig#domain_WalletConfig.terms, Revision),
            Methods = extract_withdrawal_methods(WalletTerms),
            WithdrawalLimit = extract_withdrawal_limit(WalletTerms, Currency),
            TerminalRefs = get_withdrawal_terminal_refs(WalletConfig#domain_WalletConfig.payment_institution, Revision),
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

get_withdrawal_terminal_refs(PiRef, Revision) ->
    case wapi_domain_backend:get_object(Revision, {payment_institution, PiRef}) of
        {ok, #domain_PaymentInstitution{withdrawal_routing_rules = Rules}} ->
            lists:usort(collect_ruleset_terminals(Rules, Revision));
        _ ->
            []
    end.

collect_ruleset_terminals(undefined, _Revision) ->
    [];
collect_ruleset_terminals(#domain_RoutingRules{policies = PoliciesRef}, Revision) ->
    collect_ruleset_terminals(PoliciesRef, Revision, sets:new()).

collect_ruleset_terminals(#domain_RoutingRulesetRef{} = Ref, Revision, Seen) ->
    case sets:is_element(Ref, Seen) of
        true ->
            [];
        false ->
            Seen1 = sets:add_element(Ref, Seen),
            case wapi_domain_backend:get_object(Revision, {routing_rules, Ref}) of
                {ok, #domain_RoutingRuleset{} = Ruleset} ->
                    collect_ruleset_terminals(Ruleset, Revision, Seen1);
                _ ->
                    []
            end
    end;
collect_ruleset_terminals(#domain_RoutingRuleset{decisions = Decisions}, Revision, Seen) ->
    collect_terminals_from_decisions(Decisions, Revision, Seen).

collect_terminals_from_decisions({candidates, Candidates}, _Revision, _Seen) ->
    [C#domain_RoutingCandidate.terminal || C <- Candidates];
collect_terminals_from_decisions({delegates, Delegates}, Revision, Seen) ->
    lists:flatmap(
        fun(#domain_RoutingDelegate{ruleset = Ref}) ->
            collect_ruleset_terminals(Ref, Revision, Seen)
        end,
        Delegates
    ).

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
    case get_and_check_terminal(TerminalRef, Revision) of
        {ok, #domain_Terminal{provider_ref = ProviderRef, terms = TerminalTerms}} ->
            TerminalLimit = extract_provider_limit(TerminalTerms, Currency),
            case TerminalLimit of
                undefined ->
                    ProviderTerms = get_provider_terms(ProviderRef, Revision),
                    extract_provider_limit(ProviderTerms, Currency);
                _ ->
                    TerminalLimit
            end;
        _ ->
            undefined
    end.

get_and_check_terminal(TerminalRef, Revision) ->
    case wapi_domain_backend:get_object(Revision, {terminal, TerminalRef}) of
        {ok, #domain_Terminal{terms = Terms} = Terminal} ->
            case extract_terminal_cash_limit(Terms) of
                {decisions, _} ->
                    undefined;
                _ ->
                    {ok, Terminal}
            end;
        _ ->
            undefined
    end.

extract_terminal_cash_limit(#domain_ProvisionTermSet{
    wallet = #domain_WalletProvisionTerms{
        withdrawals = #domain_WithdrawalProvisionTerms{cash_limit = CashLimit}
    }
}) ->
    CashLimit;
extract_terminal_cash_limit(_) ->
    undefined.

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

valid_range(LowerAmount, UpperAmount) when LowerAmount < UpperAmount ->
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
    #{<<"method">> => <<"WithdrawalMethodBankCard">>};
encode_withdrawal_method(digital_wallet) ->
    #{<<"method">> => <<"WithdrawalMethodDigitalWallet">>};
encode_withdrawal_method(generic) ->
    #{<<"method">> => <<"WithdrawalMethodGeneric">>}.
