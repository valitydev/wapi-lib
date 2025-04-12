-module(wapi_webhook_tests_SUITE).

-include_lib("common_test/include/ct.hrl").

-include_lib("wapi_wallet_dummy_data.hrl").
-include_lib("wapi_bouncer_data.hrl").

-include_lib("fistful_proto/include/fistful_fistful_base_thrift.hrl").
-include_lib("fistful_proto/include/fistful_fistful_thrift.hrl").
-include_lib("fistful_proto/include/fistful_account_thrift.hrl").
-include_lib("fistful_proto/include/fistful_identity_thrift.hrl").
-include_lib("fistful_proto/include/fistful_wallet_thrift.hrl").
-include_lib("fistful_proto/include/fistful_webhooker_thrift.hrl").

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
    create_webhook_ok_test/1,
    create_withdrawal_webhook_ok_test/1,
    get_webhooks_ok_test/1,
    get_webhook_ok_test/1,
    delete_webhook_ok_test/1
]).

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
            create_webhook_ok_test,
            create_withdrawal_webhook_ok_test,
            get_webhooks_ok_test,
            get_webhook_ok_test,
            delete_webhook_ok_test
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
    Party = genlib:bsuuid(),
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

-spec create_webhook_ok_test(config()) -> _.
create_webhook_ok_test(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper_bouncer:mock_assert_generic_op_ctx(
        [
            {party, ?STRING, PartyID}
        ],
        ?CTX_WAPI(#ctx_v1_WalletAPIOperation{
            id = <<"CreateWebhook">>,
            party = ?STRING
        }),
        C
    ),
    _ = wapi_ct_helper:mock_services(
        [
            {webhook_manager, fun('Create', _) -> {ok, ?WEBHOOK(?DESTINATION_EVENT_FILTER)} end},
            {fistful_identity, fun
                ('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)};
                ('Get', _) -> {ok, ?IDENTITY(PartyID)}
            end}
        ],
        C
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_webhooks_api:create_webhook/3,
        #{
            body => #{
                <<"identityID">> => ?STRING,
                <<"url">> => ?URL,
                <<"scope">> => #{
                    <<"topic">> => <<"DestinationsTopic">>,
                    <<"eventTypes">> => [<<"DestinationCreated">>]
                }
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

-spec create_withdrawal_webhook_ok_test(config()) -> _.
create_withdrawal_webhook_ok_test(C) ->
    PartyID = ?config(party, C),
    WalletID = ?STRING,
    _ = wapi_ct_helper_bouncer:mock_assert_generic_op_ctx(
        [
            {party, ?STRING, PartyID},
            {wallet, ?STRING, PartyID}
        ],
        ?CTX_WAPI(#ctx_v1_WalletAPIOperation{
            id = <<"CreateWebhook">>,
            party = ?STRING,
            wallet = ?STRING
        }),
        C
    ),
    _ = wapi_ct_helper:mock_services(
        [
            {webhook_manager, fun('Create', _) -> {ok, ?WEBHOOK_WITH_WALLET(?WITHDRAWAL_EVENT_FILTER, WalletID)} end},
            {fistful_identity, fun
                ('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)};
                ('Get', _) -> {ok, ?IDENTITY(PartyID)}
            end},
            {fistful_wallet, fun
                ('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)};
                ('Get', _) -> {ok, ?WALLET(PartyID)}
            end}
        ],
        C
    ),
    {ok, #{<<"scope">> := #{<<"walletID">> := WalletID}}} = call_api(
        fun swag_client_wallet_webhooks_api:create_webhook/3,
        #{
            body => #{
                <<"identityID">> => ?STRING,
                <<"url">> => ?URL,
                <<"scope">> => #{
                    <<"topic">> => <<"WithdrawalsTopic">>,
                    <<"walletID">> => WalletID,
                    <<"eventTypes">> => [<<"WithdrawalStarted">>]
                }
            }
        },
        ?config(context, C)
    ).

-spec get_webhooks_ok_test(config()) -> _.
get_webhooks_ok_test(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper_bouncer:mock_assert_identity_op_ctx(<<"GetWebhooks">>, ?STRING, PartyID, C),
    _ = wapi_ct_helper:mock_services(
        [
            {webhook_manager, fun('GetList', _) ->
                {ok, [?WEBHOOK(?WITHDRAWAL_EVENT_FILTER), ?WEBHOOK(?DESTINATION_EVENT_FILTER)]}
            end},
            {fistful_identity, fun
                ('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)};
                ('Get', _) -> {ok, ?IDENTITY(PartyID)}
            end}
        ],
        C
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_webhooks_api:get_webhooks/3,
        #{
            qs_val => #{
                <<"identityID">> => ?STRING
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

-spec get_webhook_ok_test(config()) -> _.
get_webhook_ok_test(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper_bouncer:mock_assert_generic_op_ctx(
        [
            {webhook, integer_to_binary(?INTEGER), #{party => ?STRING}},
            {party, ?STRING, PartyID}
        ],
        ?CTX_WAPI(#ctx_v1_WalletAPIOperation{
            id = <<"GetWebhookByID">>,
            party = ?STRING,
            webhook = integer_to_binary(?INTEGER)
        }),
        C
    ),
    _ = wapi_ct_helper:mock_services(
        [
            {webhook_manager, fun('Get', _) -> {ok, ?WEBHOOK(?WITHDRAWAL_EVENT_FILTER)} end},
            {fistful_identity, fun
                ('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)};
                ('Get', _) -> {ok, ?IDENTITY(PartyID)}
            end}
        ],
        C
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_webhooks_api:get_webhook_by_id/3,
        #{
            binding => #{
                <<"webhookID">> => integer_to_binary(?INTEGER)
            },
            qs_val => #{
                <<"identityID">> => ?STRING
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

-spec delete_webhook_ok_test(config()) -> _.
delete_webhook_ok_test(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper_bouncer:mock_assert_generic_op_ctx(
        [
            {webhook, integer_to_binary(?INTEGER), #{party => ?STRING}},
            {party, ?STRING, PartyID}
        ],
        ?CTX_WAPI(#ctx_v1_WalletAPIOperation{
            id = <<"DeleteWebhookByID">>,
            party = ?STRING,
            webhook = integer_to_binary(?INTEGER)
        }),
        C
    ),
    _ = wapi_ct_helper:mock_services(
        [
            {webhook_manager, fun
                ('Get', _) -> {ok, ?WEBHOOK(?WITHDRAWAL_EVENT_FILTER)};
                ('Delete', _) -> {ok, ok}
            end},
            {fistful_identity, fun
                ('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)};
                ('Get', _) -> {ok, ?IDENTITY(PartyID)}
            end}
        ],
        C
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_webhooks_api:delete_webhook_by_id/3,
        #{
            binding => #{
                <<"webhookID">> => integer_to_binary(?INTEGER)
            },
            qs_val => #{
                <<"identityID">> => ?STRING
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

%%

-spec call_api(function(), map(), wapi_client_lib:context()) -> {ok, term()} | {error, term()}.
call_api(F, Params, Context) ->
    {Url, PreparedParams, Opts} = wapi_client_lib:make_request(Context, Params),
    Response = F(Url, PreparedParams, Opts),
    wapi_client_lib:handle_response(Response).
