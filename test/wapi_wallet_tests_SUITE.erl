-module(wapi_wallet_tests_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").

-include_lib("wapi_wallet_dummy_data.hrl").

-include_lib("damsel/include/dmsl_domain_conf_v2_thrift.hrl").
-include_lib("damsel/include/dmsl_domain_thrift.hrl").
-include_lib("damsel/include/dmsl_payproc_thrift.hrl").

-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([init/1]).

-export([
    get_ok/1,
    get_fail_wallet_notfound/1,
    get_account_ok/1,
    get_account_fail_wallet_notfound/1,
    get_account_fail_account_notfound/1,
    get_cash_limits_ok/1
]).

-define(EMPTY_RESP(Code), {error, {Code, #{}}}).

-type test_case_name() :: atom().
-type config() :: [{atom(), any()}].
-type group_name() :: atom().

-behaviour(supervisor).

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    {ok, {#{strategy => one_for_all, intensity => 1, period => 1}, []}}.

-spec all() -> [{group, test_case_name()}].
all() ->
    [
        {group, base}
    ].

-spec groups() -> [{group_name(), list(), [test_case_name()]}].
groups() ->
    [
        {base, [], [
            get_ok,
            get_fail_wallet_notfound,
            get_account_ok,
            get_account_fail_wallet_notfound,
            get_account_fail_account_notfound,
            get_cash_limits_ok
        ]}
    ].

%%
%% starting/stopping
%%
-spec init_per_suite(config()) -> config().
init_per_suite(C) ->
    wapi_ct_helper:init_suite(?MODULE, C).

-spec end_per_suite(config()) -> _.
end_per_suite(C) ->
    _ = wapi_ct_helper:stop_mocked_service_sup(?config(suite_test_sup, C)),
    _ = [application:stop(App) || App <- ?config(apps, C)],
    ok.

-spec init_per_group(group_name(), config()) -> config().
init_per_group(Group, Config) when Group =:= base ->
    Party = ?STRING,
    Config1 = [{party, Party} | Config],
    GroupSup = wapi_ct_helper:start_mocked_service_sup(?MODULE),
    _ = wapi_ct_helper_token_keeper:mock_user_session_token(Party, GroupSup),
    [{group_test_sup, GroupSup}, {context, wapi_ct_helper:get_context(?API_TOKEN)} | Config1];
init_per_group(_, Config) ->
    Config.

-spec end_per_group(group_name(), config()) -> _.
end_per_group(_Group, C) ->
    _ = wapi_ct_helper:stop_mocked_service_sup(?config(group_test_sup, C)),
    ok.

-spec init_per_testcase(test_case_name(), config()) -> config().
init_per_testcase(Name, C) ->
    C1 = wapi_ct_helper:makeup_cfg([wapi_ct_helper:test_case_name(Name), wapi_ct_helper:woody_ctx()], C),
    [{test_sup, wapi_ct_helper:start_mocked_service_sup(?MODULE)} | C1].

-spec end_per_testcase(test_case_name(), config()) -> ok.
end_per_testcase(_Name, C) ->
    _ = wapi_ct_helper:stop_mocked_service_sup(?config(test_sup, C)),
    ok.

%%% Tests

-spec get_ok(config()) -> _.
get_ok(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper_bouncer:mock_assert_wallet_op_ctx(<<"GetWallet">>, ?STRING, PartyID, C),
    {ok, _} = get_wallet_call_api(?STRING, C).

-spec get_fail_wallet_notfound(config()) -> _.
get_fail_wallet_notfound(C) ->
    _ = wapi_ct_helper_bouncer:mock_arbiter(wapi_ct_helper_bouncer:judge_always_forbidden(), C),
    ?assertEqual(?EMPTY_RESP(404), get_wallet_call_api(<<"non existant wallet id">>, C)).

-spec get_account_ok(config()) -> _.
get_account_ok(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper_bouncer:mock_assert_wallet_op_ctx(<<"GetWalletAccount">>, ?STRING, PartyID, C),
    ok = mock_account_with_balance(?INTEGER, C),
    {ok, _} = get_account_call_api(?STRING, C).

-spec get_account_fail_wallet_notfound(config()) -> _.
get_account_fail_wallet_notfound(C) ->
    _ = wapi_ct_helper_bouncer:mock_arbiter(wapi_ct_helper_bouncer:judge_always_forbidden(), C),
    ok = mock_account_with_balance(?INTEGER, C),
    ?assertEqual(?EMPTY_RESP(401), get_account_call_api(<<"non existant wallet id">>, C)).

-spec get_account_fail_account_notfound(config()) -> _.
get_account_fail_account_notfound(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper_bouncer:mock_assert_wallet_op_ctx(<<"GetWalletAccount">>, ?STRING, PartyID, C),
    ok = mock_account_with_balance(424242, C),
    ?assertEqual({error, {404, #{}}}, get_account_call_api(?STRING, C)).

-spec get_cash_limits_ok(config()) -> _.
get_cash_limits_ok(C) ->
    PartyID = ?config(party, C),
    WalletID = ?STRING,
    OldServiceUrls = get_dmt_service_urls(),
    try
        ok = mock_wallet_limits_domain(PartyID, C),
        {ok, Limits} = wapi_wallet_limits:get_wallet_limits(PartyID, WalletID, #{}),
        ?assertEqual(expected_wallet_limits(), Limits)
    after
        ok = application:set_env(dmt_client, service_urls, OldServiceUrls)
    end.

%%

-spec call_api(function(), map(), wapi_client_lib:context()) -> {ok, term()} | {error, term()}.
call_api(F, Params, Context) ->
    {Url, PreparedParams, Opts} = wapi_client_lib:make_request(Context, Params),
    Response = F(Url, PreparedParams, Opts),
    wapi_client_lib:handle_response(Response).

get_wallet_call_api(WalletID, C) ->
    call_api(
        fun swag_client_wallet_wallets_api:get_wallet/3,
        #{
            binding => #{
                <<"walletID">> => WalletID
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

get_account_call_api(WalletID, C) ->
    call_api(
        fun swag_client_wallet_wallets_api:get_wallet_account/3,
        #{
            binding => #{
                <<"walletID">> => WalletID
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

expected_wallet_limits() ->
    [
        #{
            <<"currency">> => <<"RUB">>,
            <<"lowerBound">> => #{<<"amount">> => 300, <<"inclusive">> => true},
            <<"upperBound">> => #{<<"amount">> => 800, <<"inclusive">> => true},
            <<"withdrawalMethod">> => #{<<"method">> => <<"WithdrawalMethodBankCard">>}
        },
        #{
            <<"currency">> => <<"RUB">>,
            <<"lowerBound">> => #{<<"amount">> => 300, <<"inclusive">> => true},
            <<"upperBound">> => #{<<"amount">> => 800, <<"inclusive">> => true},
            <<"withdrawalMethod">> => #{<<"method">> => <<"WithdrawalMethodDigitalWallet">>}
        }
    ].

get_dmt_service_urls() ->
    case application:get_env(dmt_client, service_urls) of
        {ok, Urls} -> Urls;
        undefined -> #{}
    end.

mock_wallet_limits_domain(PartyID, C) ->
    CurrencyRef = #domain_CurrencyRef{symbolic_code = <<"RUB">>},
    WalletLimitRange = #domain_CashRange{
        lower = {inclusive, #domain_Cash{amount = 100, currency = CurrencyRef}},
        upper = {inclusive, #domain_Cash{amount = 1000, currency = CurrencyRef}}
    },
    WithdrawalLimitRange = #domain_CashRange{
        lower = {inclusive, #domain_Cash{amount = 200, currency = CurrencyRef}},
        upper = {inclusive, #domain_Cash{amount = 800, currency = CurrencyRef}}
    },
    TerminalLimitRange = #domain_CashRange{
        lower = {inclusive, #domain_Cash{amount = 300, currency = CurrencyRef}},
        upper = {inclusive, #domain_Cash{amount = 900, currency = CurrencyRef}}
    },
    PaymentMethods = [
        #domain_PaymentMethodRef{id = {bank_card, #domain_BankCardPaymentMethod{}}},
        #domain_PaymentMethodRef{id = {digital_wallet, #domain_PaymentServiceRef{id = <<"DW">>}}}
    ],
    TermSetHierarchyObject =
        #domain_TermSetHierarchyObject{
            ref = #domain_TermSetHierarchyRef{id = 1},
            data = #domain_TermSetHierarchy{
                term_set = #domain_TermSet{
                    wallets = #domain_WalletServiceTerms{
                        wallet_limit = {value, WalletLimitRange},
                        withdrawals = #domain_WithdrawalServiceTerms{
                            methods = {value, PaymentMethods},
                            cash_limit = {value, WithdrawalLimitRange}
                        }
                    }
                }
            }
        },
    RoutingRulesObject =
        #domain_RoutingRulesObject{
            ref = #domain_RoutingRulesetRef{id = 100},
            data = #domain_RoutingRuleset{
                name = <<"test">>,
                decisions = {candidates, [
                    #domain_RoutingCandidate{
                        allowed = {constant, true},
                        terminal = #domain_TerminalRef{id = 10}
                    }
                ]}
            }
        },
    TerminalTerms = #domain_ProvisionTermSet{
        wallet = #domain_WalletProvisionTerms{
            withdrawals = #domain_WithdrawalProvisionTerms{
                cash_limit = {value, TerminalLimitRange}
            }
        }
    },
    TerminalObject =
        #domain_TerminalObject{
            ref = #domain_TerminalRef{id = 10},
            data = #domain_Terminal{
                name = <<"test">>,
                description = <<"test">>,
                provider_ref = #domain_ProviderRef{id = 11},
                terms = TerminalTerms
            }
        },
    ProviderObject =
        #domain_ProviderObject{
            ref = #domain_ProviderRef{id = 11},
            data = #domain_Provider{
                name = <<"test">>,
                description = <<"test">>,
                proxy = #domain_Proxy{
                    ref = #domain_ProxyRef{id = 1},
                    additional = #{}
                },
                realm = test,
                terms = TerminalTerms
            }
        },
    PaymentInstitutionObject =
        #domain_PaymentInstitutionObject{
            ref = #domain_PaymentInstitutionRef{id = 1},
            data = #domain_PaymentInstitution{
                name = <<"test">>,
                system_account_set = {value, #domain_SystemAccountSetRef{id = 1}},
                inspector = {value, #domain_InspectorRef{id = 1}},
                realm = test,
                residences = [rus],
                withdrawal_routing_rules = #domain_RoutingRules{
                    policies = #domain_RoutingRulesetRef{id = 100},
                    prohibitions = #domain_RoutingRulesetRef{id = 101}
                }
            }
        },
    WalletConfigObject =
        #domain_WalletConfigObject{
            ref = #domain_WalletConfigRef{id = ?STRING},
            data = #domain_WalletConfig{
                name = ?STRING,
                block =
                    {unblocked, #domain_Unblocked{
                        reason = <<"">>,
                        since = wapi_time:rfc3339()
                    }},
                suspension =
                    {active, #domain_Active{
                        since = wapi_time:rfc3339()
                    }},
                payment_institution = #domain_PaymentInstitutionRef{id = 1},
                terms = #domain_TermSetHierarchyRef{id = 1},
                account = #domain_WalletAccount{
                    currency = CurrencyRef,
                    settlement = ?INTEGER
                },
                party_ref = #domain_PartyConfigRef{id = PartyID}
            }
        },
    DomainConfigClient = fun
        ('CheckoutObject', {{version, ?INTEGER}, {wallet_config, #domain_WalletConfigRef{id = ?STRING}}}) ->
            {ok, mk_versioned_object(wallet_config, WalletConfigObject)};
        ('CheckoutObject', {{version, ?INTEGER}, {term_set_hierarchy, #domain_TermSetHierarchyRef{id = 1}}}) ->
            {ok, mk_versioned_object(term_set_hierarchy, TermSetHierarchyObject)};
        ('CheckoutObject', {{version, ?INTEGER}, {payment_institution, #domain_PaymentInstitutionRef{id = 1}}}) ->
            {ok, mk_versioned_object(payment_institution, PaymentInstitutionObject)};
        ('CheckoutObject', {{version, ?INTEGER}, {routing_rules, #domain_RoutingRulesetRef{id = 100}}}) ->
            {ok, mk_versioned_object(routing_rules, RoutingRulesObject)};
        ('CheckoutObject', {{version, ?INTEGER}, {terminal, #domain_TerminalRef{id = 10}}}) ->
            {ok, mk_versioned_object(terminal, TerminalObject)};
        ('CheckoutObject', {{version, ?INTEGER}, {provider, #domain_ProviderRef{id = 11}}}) ->
            {ok, mk_versioned_object(provider, ProviderObject)};
        ('CheckoutObject', _) ->
            woody_error:raise(business, #domain_conf_v2_ObjectNotFound{})
    end,
    DomainConfig = fun('GetLatestVersion', _) -> {ok, ?INTEGER} end,
    _ = wapi_ct_helper:mock_services(
        [
            {domain_config, DomainConfig},
            {domain_config_client, DomainConfigClient}
        ],
        C
    ),
    ok.

mk_versioned_object(Type, Object) ->
    #domain_conf_v2_VersionedObject{
        info = #domain_conf_v2_VersionedObjectInfo{
            version = ?INTEGER,
            changed_at = genlib_rfc3339:format(genlib_time:unow(), second),
            changed_by = #domain_conf_v2_Author{
                id = ?STRING,
                name = ?STRING,
                email = ?STRING
            }
        },
        object = {Type, Object}
    }.

mock_account_with_balance(ExistingAccountID, C) ->
    _ = wapi_ct_helper:mock_services(
        [
            {party_management, fun
                ('GetAccountState', {_, AccountID, ?INTEGER}) when AccountID =:= ExistingAccountID ->
                    {ok, #payproc_AccountState{
                        account_id = AccountID,
                        own_amount = ?INTEGER,
                        available_amount = ?INTEGER,
                        currency = #domain_Currency{
                            name = ?STRING,
                            symbolic_code = ?RUB,
                            numeric_code = ?INTEGER,
                            exponent = ?INTEGER
                        }
                    }};
                ('GetAccountState', {_PartyID, _AccountID, _DomainRevision}) ->
                    throw(#payproc_AccountNotFound{})
            end}
        ],
        C
    ),
    ok.
