-module(wapi_tests_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-include_lib("wapi_wallet_dummy_data.hrl").

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
    map_schema_violated_error_ok/1,
    map_wrong_body_error_ok/1
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
            map_schema_violated_error_ok,
            map_wrong_body_error_ok
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
    [{context, wapi_ct_helper:get_context(?API_TOKEN)} | Config1];
init_per_group(_, Config) ->
    Config.

-spec end_per_group(group_name(), config()) -> _.
end_per_group(_Group, _C) ->
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

-spec map_schema_violated_error_ok(config()) -> _.
map_schema_violated_error_ok(C) ->
    Context = wapi_ct_helper:cfg(context, C),
    Params = #{},
    {Endpoint, PreparedParams, Opts0} = wapi_client_lib:make_request(Context, Params),
    Url = swag_client_wallet_utils:get_url(Endpoint, "/wallet/v0/w2w/transfers"),
    Headers = maps:to_list(maps:get(header, PreparedParams)),
    Body = <<"{}">>,
    Opts = Opts0 ++ [with_body],
    {ok, 400, _, Error} = hackney:request(
        post,
        Url,
        Headers,
        Body,
        Opts
    ),
    ExpectedError = make_mapped_error(
        "W2WTransferParameters", "SchemaViolated", ", description: Missing required property: body."
    ),
    ?assertEqual(
        ExpectedError,
        Error
    ).

-spec map_wrong_body_error_ok(config()) -> _.
map_wrong_body_error_ok(C) ->
    Context = wapi_ct_helper:cfg(context, C),
    Params = #{},
    {Endpoint, PreparedParams, Opts0} = wapi_client_lib:make_request(Context, Params),
    Url = swag_client_wallet_utils:get_url(Endpoint, "/wallet/v0/w2w/transfers"),
    Headers = maps:to_list(maps:get(header, PreparedParams)),
    LongBinary =
        <<
            "LongBinaryLongBinaryLongBinaryLongBinaryLongBinaryLong\n"
            "    BinaryLongBinaryLongBinaryLongBinaryLongBinaryLongBinary"
        >>,
    Body = <<"{", LongBinary/binary, LongBinary/binary, LongBinary/binary, LongBinary/binary, LongBinary/binary, "}">>,
    Opts = Opts0 ++ [with_body],
    {ok, 400, _, Error} = hackney:request(
        post,
        Url,
        Headers,
        Body,
        Opts
    ),
    ExpectedError = make_mapped_error("W2WTransferParameters", "WrongBody", ", description: Invalid json"),
    ?assertEqual(
        ExpectedError,
        Error
    ).

make_mapped_error(Name, Type, Desc) ->
    Format = <<"{\"description\":\"Request parameter: ~s, error type: ~s~s\",\"errorType\":\"~s\",\"name\":\"~s\"}">>,
    genlib:to_binary(io_lib:format(Format, [Name, Type, Desc, Type, Name])).
