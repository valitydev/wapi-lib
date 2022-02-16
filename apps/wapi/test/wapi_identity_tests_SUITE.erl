-module(wapi_identity_tests_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-include_lib("wapi_wallet_dummy_data.hrl").

-include_lib("fistful_proto/include/ff_proto_identity_thrift.hrl").

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
    create_identity/1,
    create_identity_provider_notfound/1,
    create_identity_party_notfound/1,
    create_identity_party_inaccessible/1,
    create_identity_thrift_name/1,
    get_identity/1,
    get_identity_notfound/1
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
            create_identity,
            create_identity_provider_notfound,
            create_identity_party_notfound,
            create_identity_party_inaccessible,
            create_identity_thrift_name,
            get_identity,
            get_identity_notfound
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
    wapi_ct_helper:stop_mocked_service_sup(?config(test_sup, C)),
    ok.

%%% Tests
-spec create_identity(config()) -> _.
create_identity(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper_bouncer:mock_assert_party_op_ctx(<<"CreateIdentity">>, PartyID, C),
    _ = wapi_ct_helper:mock_services(
        [
            {bender_thrift, fun('GenerateID', _) -> {ok, ?GENERATE_ID_RESULT} end},
            {fistful_identity, fun('Create', _) -> {ok, ?IDENTITY(PartyID)} end}
        ],
        C
    ),
    {ok, _} = create_identity_call_api(C).

-spec create_identity_provider_notfound(config()) -> _.
create_identity_provider_notfound(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper_bouncer:mock_assert_party_op_ctx(<<"CreateIdentity">>, PartyID, C),
    _ = wapi_ct_helper:mock_services(
        [
            {bender_thrift, fun('GenerateID', _) -> {ok, ?GENERATE_ID_RESULT} end},
            {fistful_identity, fun('Create', _) -> {throwing, #fistful_ProviderNotFound{}} end}
        ],
        C
    ),
    ?assertEqual(
        {error, {422, #{<<"message">> => <<"No such provider">>}}},
        create_identity_call_api(C)
    ).

-spec create_identity_party_notfound(config()) -> _.
create_identity_party_notfound(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper_bouncer:mock_assert_party_op_ctx(<<"CreateIdentity">>, PartyID, C),
    _ = wapi_ct_helper:mock_services(
        [
            {bender_thrift, fun('GenerateID', _) -> {ok, ?GENERATE_ID_RESULT} end},
            {fistful_identity, fun('Create', _) -> {throwing, #fistful_PartyNotFound{}} end}
        ],
        C
    ),
    ?assertEqual(
        {error, {422, #{<<"message">> => <<"Party does not exist">>}}},
        create_identity_call_api(C)
    ).

-spec create_identity_party_inaccessible(config()) -> _.
create_identity_party_inaccessible(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper_bouncer:mock_assert_party_op_ctx(<<"CreateIdentity">>, PartyID, C),
    _ = wapi_ct_helper:mock_services(
        [
            {bender_thrift, fun('GenerateID', _) -> {ok, ?GENERATE_ID_RESULT} end},
            {fistful_identity, fun('Create', _) -> {throwing, #fistful_PartyInaccessible{}} end}
        ],
        C
    ),
    ?assertEqual(
        {error, {422, #{<<"message">> => <<"Identity inaccessible">>}}},
        create_identity_call_api(C)
    ).

-spec create_identity_thrift_name(config()) -> _.
create_identity_thrift_name(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper_bouncer:mock_assert_party_op_ctx(<<"CreateIdentity">>, PartyID, C),
    _ = wapi_ct_helper:mock_services(
        [
            {bender_thrift, fun('GenerateID', _) -> {ok, ?GENERATE_ID_RESULT} end},
            {fistful_identity, fun('Create', _) -> {ok, ?IDENTITY(PartyID, ?DEFAULT_CONTEXT_NO_NAME(PartyID))} end}
        ],
        C
    ),
    {ok, #{<<"name">> := ?STRING}} = create_identity_call_api(C).

-spec get_identity(config()) -> _.
get_identity(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper_bouncer:mock_assert_identity_op_ctx(<<"GetIdentity">>, ?STRING, PartyID, C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_identity, fun('Get', _) -> {ok, ?IDENTITY(PartyID)} end}
        ],
        C
    ),
    {ok, _} = get_identity_call_api(C).

-spec get_identity_notfound(config()) -> _.
get_identity_notfound(C) ->
    _ = wapi_ct_helper_bouncer:mock_arbiter(_ = wapi_ct_helper_bouncer:judge_always_forbidden(), C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_identity, fun('Get', _) -> {throwing, #fistful_IdentityNotFound{}} end}
        ],
        C
    ),
    ?assertEqual(
        {error, {404, #{}}},
        get_identity_call_api(C)
    ).

%%

create_identity_call_api(C) ->
    call_api(
        fun swag_client_wallet_identities_api:create_identity/3,
        #{
            body => #{
                <<"name">> => ?STRING,
                <<"provider">> => ?STRING,
                <<"metadata">> => #{
                    <<"somedata">> => ?STRING
                }
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

get_identity_call_api(C) ->
    call_api(
        fun swag_client_wallet_identities_api:get_identity/3,
        #{
            binding => #{
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
