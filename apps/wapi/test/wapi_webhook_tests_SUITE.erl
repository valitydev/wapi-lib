-module(wapi_webhook_tests_SUITE).

-include_lib("common_test/include/ct.hrl").

-include_lib("damsel/include/dmsl_domain_config_thrift.hrl").

-include_lib("jose/include/jose_jwk.hrl").
-include_lib("wapi_wallet_dummy_data.hrl").
-include_lib("wapi_bouncer_data.hrl").

-include_lib("fistful_proto/include/ff_proto_identity_thrift.hrl").
-include_lib("fistful_proto/include/ff_proto_wallet_thrift.hrl").
-include_lib("fistful_proto/include/ff_proto_webhooker_thrift.hrl").

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

-define(badresp(Code), {error, {invalid_response_code, Code}}).
-define(emptyresp(Code), {error, {Code, #{}}}).

-type test_case_name() :: atom().
-type config() :: [{atom(), any()}].
-type group_name() :: atom().

% common-api is used since it is the domain used in production RN
% TODO: change to wallet-api (or just omit since it is the default one) when new tokens will be a thing
-define(DOMAIN, <<"common-api">>).

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

-spec create_webhook_ok_test(config()) -> _.
create_webhook_ok_test(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper_bouncer:mock_assert_generic_op_ctx(
        [
            {identity, ?STRING, PartyID}
        ],
        ?CTX_WAPI(#bctx_v1_WalletAPIOperation{
            id = <<"CreateWebhook">>,
            identity = ?STRING
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
                <<"url">> => ?STRING,
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
            {identity, ?STRING, PartyID},
            {wallet, ?STRING, PartyID}
        ],
        ?CTX_WAPI(#bctx_v1_WalletAPIOperation{
            id = <<"CreateWebhook">>,
            identity = ?STRING,
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
                <<"url">> => ?STRING,
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
            {webhook, integer_to_binary(?INTEGER), #{identity => ?STRING}},
            {identity, ?STRING, PartyID}
        ],
        ?CTX_WAPI(#bctx_v1_WalletAPIOperation{
            id = <<"GetWebhookByID">>,
            identity = ?STRING,
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
            {webhook, integer_to_binary(?INTEGER), #{identity => ?STRING}},
            {identity, ?STRING, PartyID}
        ],
        ?CTX_WAPI(#bctx_v1_WalletAPIOperation{
            id = <<"DeleteWebhookByID">>,
            identity = ?STRING,
            webhook = integer_to_binary(?INTEGER)
        }),
        C
    ),
    _ = wapi_ct_helper:mock_services(
        [
            {webhook_manager, fun('Delete', _) -> {ok, ok} end},
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
