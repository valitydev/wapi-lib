-module(wapi_provider_tests_SUITE).

-include_lib("common_test/include/ct.hrl").

-include_lib("wapi_wallet_dummy_data.hrl").

-include_lib("fistful_proto/include/ff_proto_provider_thrift.hrl").

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
    get_provider_ok/1,
    get_provider_fail_notfound/1,
    list_providers/1
]).

% common-api is used since it is the domain used in production RN
% TODO: change to wallet-api (or just omit since it is the default one) when new tokens will be a thing
-define(DOMAIN, <<"common-api">>).

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
            get_provider_ok,
            get_provider_fail_notfound,
            list_providers
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

-spec get_provider_ok(config()) -> _.
get_provider_ok(C) ->
    _ = wapi_ct_helper_bouncer:mock_assert_op_ctx(<<"GetProvider">>, C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_provider, fun('GetProvider', _) -> {ok, ?PROVIDER} end}
        ],
        C
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_providers_api:get_provider/3,
        #{
            binding => #{
                <<"providerID">> => ?STRING
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

-spec get_provider_fail_notfound(config()) -> _.
get_provider_fail_notfound(C) ->
    _ = wapi_ct_helper_bouncer:mock_assert_op_ctx(<<"GetProvider">>, C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_provider, fun('GetProvider', _) -> {throwing, #fistful_ProviderNotFound{}} end}
        ],
        C
    ),
    {error, {404, #{}}} = call_api(
        fun swag_client_wallet_providers_api:get_provider/3,
        #{
            binding => #{
                <<"providerID">> => ?STRING
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

-spec list_providers(config()) -> _.
list_providers(C) ->
    _ = wapi_ct_helper_bouncer:mock_assert_op_ctx(<<"ListProviders">>, C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_provider, fun('ListProviders', _) -> {ok, [?PROVIDER, ?PROVIDER]} end}
        ],
        C
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_providers_api:list_providers/3,
        #{
            qs_val => #{
                <<"residence">> => ?RESIDENCE_RUS
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
