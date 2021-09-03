-module(wapi_stat_tests_SUITE).

-include_lib("common_test/include/ct.hrl").

-include_lib("wapi_wallet_dummy_data.hrl").

-include_lib("fistful_proto/include/ff_proto_fistful_stat_thrift.hrl").

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
    list_wallets/1,
    list_wallets_invalid_error/1,
    list_wallets_bad_token_error/1,
    list_withdrawals/1,
    list_withdrawals_invalid_error/1,
    list_withdrawals_bad_token_error/1,
    list_deposits/1,
    list_deposits_invalid_error/1,
    list_deposits_bad_token_error/1,
    list_destinations/1,
    list_destinations_invalid_error/1,
    list_destinations_bad_token_error/1,
    list_identities/1,
    list_identities_invalid_error/1,
    list_identities_bad_token_error/1,
    list_deposit_revert/1,
    list_deposit_revert_invalid_error/1,
    list_deposit_revert_bad_token_error/1,
    list_deposit_adjustment_wo_changes_plan/1,
    list_deposit_adjustment_with_changes_plan/1,
    list_deposit_adjustment_invalid_error/1,
    list_deposit_adjustment_bad_token_error/1
]).

% common-api is used since it is the domain used in production RN
% TODO: change to wallet-api (or just omit since it is the default one) when new tokens will be a thing
-define(DOMAIN, <<"common-api">>).
-define(badresp(Code), {error, {invalid_response_code, Code}}).
-define(emptyresp(Code), {error, {Code, #{}}}).

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
            list_wallets,
            list_wallets_invalid_error,
            list_wallets_bad_token_error,
            list_withdrawals,
            list_withdrawals_invalid_error,
            list_withdrawals_bad_token_error,
            list_deposits,
            list_deposits_invalid_error,
            list_deposits_bad_token_error,
            list_destinations,
            list_destinations_invalid_error,
            list_destinations_bad_token_error,
            list_identities,
            list_identities_invalid_error,
            list_identities_bad_token_error,
            list_deposit_revert,
            list_deposit_revert_invalid_error,
            list_deposit_revert_bad_token_error,
            list_deposit_adjustment_wo_changes_plan,
            list_deposit_adjustment_with_changes_plan,
            list_deposit_adjustment_invalid_error,
            list_deposit_adjustment_bad_token_error
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
    ok = wapi_context:save(
        wapi_context:create(#{
            woody_context => woody_context:new(<<"init_per_group/", (atom_to_binary(Group, utf8))/binary>>)
        })
    ),
    Party = genlib:bsuuid(),
    {ok, Token} = wapi_ct_helper:issue_token(Party, [{[party], write}], unlimited, ?DOMAIN),
    Config1 = [{party, Party} | Config],
    [{context, wapi_ct_helper:get_context(Token)} | Config1];
init_per_group(_, Config) ->
    Config.

-spec end_per_group(group_name(), config()) -> _.
end_per_group(_Group, _C) ->
    ok.

-spec init_per_testcase(test_case_name(), config()) -> config().
init_per_testcase(Name, C) ->
    C1 = wapi_ct_helper:makeup_cfg([wapi_ct_helper:test_case_name(Name), wapi_ct_helper:woody_ctx()], C),
    ok = wapi_context:save(C1),
    [{test_sup, wapi_ct_helper:start_mocked_service_sup(?MODULE)} | C1].

-spec end_per_testcase(test_case_name(), config()) -> config().
end_per_testcase(_Name, C) ->
    ok = wapi_context:cleanup(),
    _ = wapi_ct_helper:stop_mocked_service_sup(?config(test_sup, C)),
    ok.

%%% Tests

-spec list_wallets(config()) -> _.
list_wallets(C) ->
    _ = wapi_ct_helper_bouncer:mock_assert_op_ctx(<<"ListWallets">>, C),
    wapi_ct_helper:mock_services(
        [
            {fistful_stat, fun('GetWallets', _) -> {ok, ?STAT_RESPONCE(?STAT_WALLETS)} end}
        ],
        C
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_wallets_api:list_wallets/3,
        #{
            qs_val => #{
                <<"limit">> => <<"123">>
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

-spec list_wallets_invalid_error(config()) -> _.
list_wallets_invalid_error(C) ->
    MockFunc = fun('GetWallets', _) -> {throwing, ?STAT_INVALID_EXCEPTION([<<"Error 1">>, <<"Error 2">>])} end,
    SwagFunc = fun swag_client_wallet_wallets_api:list_wallets/3,
    check_invalid_error(<<"ListWallets">>, MockFunc, SwagFunc, C).

-spec list_wallets_bad_token_error(config()) -> _.
list_wallets_bad_token_error(C) ->
    MockFunc = fun('GetWallets', _) -> {throwing, ?STAT_BADTOKEN_EXCEPTION} end,
    SwagFunc = fun swag_client_wallet_wallets_api:list_wallets/3,
    check_bad_token_error(<<"ListWallets">>, MockFunc, SwagFunc, C).

-spec list_withdrawals(config()) -> _.
list_withdrawals(C) ->
    _ = wapi_ct_helper_bouncer:mock_assert_op_ctx(<<"ListWithdrawals">>, C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_stat, fun('GetWithdrawals', _) -> {ok, ?STAT_RESPONCE(?STAT_WITHDRAWALS)} end}
        ],
        C
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_withdrawals_api:list_withdrawals/3,
        #{
            qs_val => #{
                <<"limit">> => <<"123">>
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

-spec list_withdrawals_invalid_error(config()) -> _.
list_withdrawals_invalid_error(C) ->
    MockFunc = fun('GetWithdrawals', _) -> {throwing, ?STAT_INVALID_EXCEPTION([<<"Error 1">>, <<"Error 2">>])} end,
    SwagFunc = fun swag_client_wallet_withdrawals_api:list_withdrawals/3,
    check_invalid_error(<<"ListWithdrawals">>, MockFunc, SwagFunc, C).

-spec list_withdrawals_bad_token_error(config()) -> _.
list_withdrawals_bad_token_error(C) ->
    MockFunc = fun('GetWithdrawals', _) -> {throwing, ?STAT_BADTOKEN_EXCEPTION} end,
    SwagFunc = fun swag_client_wallet_withdrawals_api:list_withdrawals/3,
    check_bad_token_error(<<"ListWithdrawals">>, MockFunc, SwagFunc, C).

-spec list_deposits(config()) -> _.
list_deposits(C) ->
    _ = wapi_ct_helper_bouncer:mock_assert_op_ctx(<<"ListDeposits">>, C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_stat, fun('GetDeposits', _) -> {ok, ?STAT_RESPONCE(?STAT_DEPOSITS)} end}
        ],
        C
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_deposits_api:list_deposits/3,
        #{
            qs_val => #{
                <<"limit">> => <<"123">>
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

-spec list_deposits_invalid_error(config()) -> _.
list_deposits_invalid_error(C) ->
    MockFunc = fun('GetDeposits', _) -> {throwing, ?STAT_INVALID_EXCEPTION([<<"Error 1">>, <<"Error 2">>])} end,
    SwagFunc = fun swag_client_wallet_deposits_api:list_deposits/3,
    check_invalid_error(<<"ListDeposits">>, MockFunc, SwagFunc, C).

-spec list_deposits_bad_token_error(config()) -> _.
list_deposits_bad_token_error(C) ->
    MockFunc = fun('GetDeposits', _) -> {throwing, ?STAT_BADTOKEN_EXCEPTION} end,
    SwagFunc = fun swag_client_wallet_deposits_api:list_deposits/3,
    check_bad_token_error(<<"ListDeposits">>, MockFunc, SwagFunc, C).

-spec list_destinations(config()) -> _.
list_destinations(C) ->
    _ = wapi_ct_helper_bouncer:mock_assert_op_ctx(<<"ListDestinations">>, C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_stat, fun('GetDestinations', _) -> {ok, ?STAT_RESPONCE(?STAT_DESTINATIONS)} end}
        ],
        C
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_withdrawals_api:list_destinations/3,
        #{
            qs_val => #{
                <<"limit">> => <<"123">>
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

-spec list_destinations_invalid_error(config()) -> _.
list_destinations_invalid_error(C) ->
    MockFunc = fun('GetDestinations', _) -> {throwing, ?STAT_INVALID_EXCEPTION([<<"Error 1">>, <<"Error 2">>])} end,
    SwagFunc = fun swag_client_wallet_withdrawals_api:list_destinations/3,
    check_invalid_error(<<"ListDestinations">>, MockFunc, SwagFunc, C).

-spec list_destinations_bad_token_error(config()) -> _.
list_destinations_bad_token_error(C) ->
    MockFunc = fun('GetDestinations', _) -> {throwing, ?STAT_BADTOKEN_EXCEPTION} end,
    SwagFunc = fun swag_client_wallet_withdrawals_api:list_destinations/3,
    check_bad_token_error(<<"ListDestinations">>, MockFunc, SwagFunc, C).

-spec list_identities(config()) -> _.
list_identities(C) ->
    _ = wapi_ct_helper_bouncer:mock_assert_op_ctx(<<"ListIdentities">>, C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_stat, fun('GetIdentities', _) -> {ok, ?STAT_RESPONCE(?STAT_IDENTITIES)} end}
        ],
        C
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_identities_api:list_identities/3,
        #{
            qs_val => #{
                <<"limit">> => <<"123">>
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

-spec list_identities_invalid_error(config()) -> _.
list_identities_invalid_error(C) ->
    MockFunc = fun('GetIdentities', _) -> {throwing, ?STAT_INVALID_EXCEPTION([<<"Error 1">>, <<"Error 2">>])} end,
    SwagFunc = fun swag_client_wallet_identities_api:list_identities/3,
    check_invalid_error(<<"ListIdentities">>, MockFunc, SwagFunc, C).

-spec list_identities_bad_token_error(config()) -> _.
list_identities_bad_token_error(C) ->
    MockFunc = fun('GetIdentities', _) -> {throwing, ?STAT_BADTOKEN_EXCEPTION} end,
    SwagFunc = fun swag_client_wallet_identities_api:list_identities/3,
    check_bad_token_error(<<"ListIdentities">>, MockFunc, SwagFunc, C).

-spec list_deposit_revert(config) -> _.
list_deposit_revert(Cfg) ->
    _ = wapi_ct_helper_bouncer:mock_assert_op_ctx(<<"ListDepositReverts">>, Cfg),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_stat, fun('GetDepositReverts', _) -> {ok, ?STAT_RESPONCE(?STAT_DEPOSIT_REVERTS)} end}
        ],
        Cfg
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_deposits_api:list_deposit_reverts/3,
        #{
            qs_val => #{
                <<"limit">> => <<"123">>
            }
        },
        wapi_ct_helper:cfg(context, Cfg)
    ).

-spec list_deposit_revert_invalid_error(config) -> _.
list_deposit_revert_invalid_error(Cfg) ->
    MockFunc = fun('GetDepositReverts', _) -> {throwing, ?STAT_INVALID_EXCEPTION([<<"Error 1">>, <<"Error 2">>])} end,
    SwagFunc = fun swag_client_wallet_deposits_api:list_deposit_reverts/3,
    check_invalid_error(<<"ListDepositReverts">>, MockFunc, SwagFunc, Cfg).

-spec list_deposit_revert_bad_token_error(config) -> _.
list_deposit_revert_bad_token_error(Cfg) ->
    MockFunc = fun('GetDepositReverts', _) -> {throwing, ?STAT_BADTOKEN_EXCEPTION} end,
    SwagFunc = fun swag_client_wallet_deposits_api:list_deposit_reverts/3,
    check_bad_token_error(<<"ListDepositReverts">>, MockFunc, SwagFunc, Cfg).

-spec list_deposit_adjustment_wo_changes_plan(config) -> _.
list_deposit_adjustment_wo_changes_plan(Cfg) ->
    _ = wapi_ct_helper_bouncer:mock_assert_op_ctx(<<"ListDepositAdjustments">>, Cfg),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_stat, fun('GetDepositAdjustments', _) ->
                {ok, ?STAT_RESPONCE(?STAT_DEPOSIT_ADJUSTMENTS_WO_CANGES_PLAN)}
            end}
        ],
        Cfg
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_deposits_api:list_deposit_adjustments/3,
        #{
            qs_val => #{
                <<"limit">> => <<"123">>
            }
        },
        wapi_ct_helper:cfg(context, Cfg)
    ).

-spec list_deposit_adjustment_with_changes_plan(config) -> _.
list_deposit_adjustment_with_changes_plan(Cfg) ->
    _ = wapi_ct_helper_bouncer:mock_assert_op_ctx(<<"ListDepositAdjustments">>, Cfg),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_stat, fun('GetDepositAdjustments', _) ->
                {ok, ?STAT_RESPONCE(?STAT_DEPOSIT_ADJUSTMENTS_WITH_CANGES_PLAN)}
            end}
        ],
        Cfg
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_deposits_api:list_deposit_adjustments/3,
        #{
            qs_val => #{
                <<"limit">> => <<"123">>
            }
        },
        wapi_ct_helper:cfg(context, Cfg)
    ).

-spec list_deposit_adjustment_invalid_error(config) -> _.
list_deposit_adjustment_invalid_error(Cfg) ->
    MockFunc = fun('GetDepositAdjustments', _) ->
        {throwing, ?STAT_INVALID_EXCEPTION([<<"Error 1">>, <<"Error 2">>])}
    end,
    SwagFunc = fun swag_client_wallet_deposits_api:list_deposit_adjustments/3,
    check_invalid_error(<<"ListDepositAdjustments">>, MockFunc, SwagFunc, Cfg).

-spec list_deposit_adjustment_bad_token_error(config) -> _.
list_deposit_adjustment_bad_token_error(Cfg) ->
    MockFunc = fun('GetDepositAdjustments', _) -> {throwing, ?STAT_BADTOKEN_EXCEPTION} end,
    SwagFunc = fun swag_client_wallet_deposits_api:list_deposit_adjustments/3,
    check_bad_token_error(<<"ListDepositAdjustments">>, MockFunc, SwagFunc, Cfg).

%%

check_invalid_error(OpName, MockFunc, SwagFunc, C) ->
    check_error(OpName, <<"NoMatch">>, MockFunc, SwagFunc, C).

check_bad_token_error(OpName, MockFunc, SwagFunc, C) ->
    check_error(OpName, <<"InvalidToken">>, MockFunc, SwagFunc, C).

check_error(OpName, Error, MockFunc, SwagFunc, C) ->
    _ = wapi_ct_helper_bouncer:mock_assert_op_ctx(OpName, C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_stat, MockFunc}
        ],
        C
    ),
    {error, {400, #{<<"errorType">> := Error}}} = call_api(
        SwagFunc,
        #{
            qs_val => #{
                <<"limit">> => <<"123">>
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

-spec call_api(function(), map(), wapi_client_lib:context()) -> {ok, term()} | {error, term()}.
call_api(F, Params, Context) ->
    {Url, PreparedParams, Opts} = wapi_client_lib:make_request(Context, Params),
    Response = F(Url, PreparedParams, Opts),
    wapi_client_lib:handle_response(Response).
