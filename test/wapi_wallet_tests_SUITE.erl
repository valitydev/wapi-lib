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
    Config = wapi_ct_helper:init_suite(?MODULE, C),
    SupPid = ?config(suite_test_sup, Config),
    ok = init_party_management_mock(SupPid),
    Config.

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
    WalletID = ?WALLET_ID_OK,
    _ = wapi_ct_helper_bouncer:mock_assert_wallet_op_ctx(<<"GetWalletCashLimits">>, WalletID, PartyID, C),
    {ok, Limits} = get_cash_limits_call_api(WalletID, PartyID, C),
    %% Both terminals: lower 200 from routing (term1), upper 500 from wallet
    ?assertEqual(expected_wallet_limits(), Limits).

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

get_cash_limits_call_api(WalletID, PartyID, C) ->
    call_api(
        fun swag_client_wallet_wallets_api:get_wallet_cash_limits/3,
        #{
            binding => #{
                <<"walletID">> => WalletID
            },
            qs_val => #{
                <<"partyID">> => PartyID
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

expected_wallet_limits() ->
    expected_wallet_limits(200, 500).

expected_wallet_limits(LowerBound, UpperBound) ->
    [
        #{
            <<"currency">> => <<"RUB">>,
            <<"lowerBound">> => #{<<"amount">> => LowerBound, <<"inclusive">> => true},
            <<"upperBound">> => #{<<"amount">> => UpperBound, <<"inclusive">> => true},
            <<"withdrawalMethod">> => #{
                <<"method">> => <<"WithdrawalMethodBankCard">>,
                <<"paymentSystems">> => []
            }
        },
        #{
            <<"currency">> => <<"RUB">>,
            <<"lowerBound">> => #{<<"amount">> => LowerBound, <<"inclusive">> => true},
            <<"upperBound">> => #{<<"amount">> => UpperBound, <<"inclusive">> => true},
            <<"withdrawalMethod">> => #{
                <<"method">> => <<"WithdrawalMethodDigitalWallet">>,
                <<"providers">> => []
            }
        }
    ].

mock_account_with_balance(ExistingAccountID, _C) ->
    set_party_management_account(ExistingAccountID).

%% Party management mock (GetAccountState, ComputeRoutingRuleset for wallet limits)
-spec init_party_management_mock(pid()) -> ok.
init_party_management_mock(SupPid) ->
    RoutingFun = default_party_management_routing(),
    PartyManagement = fun
        ('ComputeRoutingRuleset', X) ->
            RoutingFun('ComputeRoutingRuleset', X);
        ('GetAccountState', {_PartyRef, AccountID, ?INTEGER}) ->
            case application:get_env(wapi_lib, test_account_id, undefined) of
                AccountID ->
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
                _ ->
                    throw(#payproc_AccountNotFound{})
            end
    end,
    _ = wapi_ct_helper:mock_services([{party_management, PartyManagement}], SupPid),
    ok.

-spec set_party_management_account(integer() | undefined) -> ok.
set_party_management_account(AccountID) ->
    application:set_env(wapi_lib, test_account_id, AccountID).

-spec default_party_management_routing() -> fun().
default_party_management_routing() ->
    Allowed = {constant, true},
    fun('ComputeRoutingRuleset', {#domain_RoutingRulesetRef{id = 100}, _V, _Varset}) ->
        {ok, #domain_RoutingRuleset{
            name = <<"both">>,
            decisions =
                {candidates, [
                    #domain_RoutingCandidate{allowed = Allowed, terminal = #domain_TerminalRef{id = 10}},
                    #domain_RoutingCandidate{allowed = Allowed, terminal = #domain_TerminalRef{id = 20}}
                ]}
        }}
    end.
