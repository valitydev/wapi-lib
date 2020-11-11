-module(wapi_ct_helper).

-include_lib("common_test/include/ct.hrl").
-include_lib("wapi_wallet_dummy_data.hrl").
-include_lib("damsel/include/dmsl_domain_config_thrift.hrl").

-export([cfg/2]).
-export([cfg/3]).
-export([makeup_cfg/2]).
-export([woody_ctx/0]).
-export([get_woody_ctx/1]).
-export([test_case_name/1]).
-export([get_test_case_name/1]).

-export([init_suite/2]).
-export([start_app/1]).
-export([start_app/2]).
-export([issue_token/4]).
-export([get_context/1]).
-export([get_keysource/2]).
-export([start_mocked_service_sup/1]).
-export([stop_mocked_service_sup/1]).
-export([mock_services/2]).
-export([mock_services_/2]).
-export([get_lifetime/0]).
-export([create_auth_ctx/1]).

-define(WAPI_IP,        "::").
-define(WAPI_PORT,      8080).
-define(WAPI_HOST_NAME, "localhost").
-define(WAPI_URL,       ?WAPI_HOST_NAME ++ ":" ++ integer_to_list(?WAPI_PORT)).
-define(DOMAIN,         <<"wallet-api">>).

%%
-type config() :: [{atom(), any()}].
-type test_case_name() :: atom().
-type app_name() :: atom().
-type app_env() :: [{atom(), term()}].

-define(SIGNEE, wapi).

-spec cfg(atom(), config()) -> term().

cfg(Key, Config) ->
    case lists:keyfind(Key, 1, Config) of
        {Key, V} -> V;
        _        -> error({'ct config entry missing', Key})
    end.

-spec cfg(atom(), _, config()) -> config().

cfg(Key, Value, Config) ->
    lists:keystore(Key, 1, Config, {Key, Value}).

-type config_mut_fun() :: fun((config()) -> config()).

-spec makeup_cfg([config_mut_fun()], config()) -> config().

makeup_cfg(CMFs, C0) ->
    lists:foldl(fun (CMF, C) -> CMF(C) end, C0, CMFs).

-spec woody_ctx() -> config_mut_fun().

woody_ctx() ->
    fun (C) -> cfg('$woody_ctx', construct_woody_ctx(C), C) end.

construct_woody_ctx(C) ->
    woody_context:new(construct_rpc_id(get_test_case_name(C))).

construct_rpc_id(TestCaseName) ->
    woody_context:new_rpc_id(
        <<"undefined">>,
        list_to_binary(lists:sublist(atom_to_list(TestCaseName), 32)),
        woody_context:new_req_id()
    ).

-spec get_woody_ctx(config()) -> woody_context:ctx().

get_woody_ctx(C) ->
    cfg('$woody_ctx', C).

%%

-spec test_case_name(test_case_name()) -> config_mut_fun().

test_case_name(TestCaseName) ->
    fun (C) -> cfg('$test_case_name', TestCaseName, C) end.

-spec get_test_case_name(config()) -> test_case_name().

get_test_case_name(C) ->
    cfg('$test_case_name', C).

%

-spec init_suite(module(), config()) ->
    config().
init_suite(Module, Config) ->
    SupPid = start_mocked_service_sup(Module),
    Apps1 =
        start_app(scoper) ++
        start_app(woody) ++
        start_app({wapi, Config}),
    [{apps, lists:reverse(Apps1)}, {suite_test_sup, SupPid} | Config].

-spec start_app(app_name()) ->
    [app_name()].

start_app(scoper = AppName) ->
    start_app_with(AppName, [
        {storage, scoper_storage_logger}
    ]);

start_app(woody = AppName) ->
    start_app_with(AppName, [
        {acceptors_pool_size, 4}
    ]);

start_app({wapi = AppName, Config}) ->
    JwkPath = get_keysource("jwk.json", Config),
    start_app_with(AppName, [
        {ip, "::"},
        {port, 8080},
        {realm, <<"external">>},
        {public_endpoint, <<"localhost:8080">>},
        {access_conf, #{
            jwt => #{
                keyset => #{
                    wapi     => {pem_file, get_keysource("private.pem", Config)}
                }
            }
        }},
        {signee, wapi},
        {lechiffre_opts,  #{
            encryption_key_path => JwkPath,
            decryption_key_paths => [JwkPath]
        }},
        {swagger_handler_opts, #{
            validation_opts => #{
                custom_validator => wapi_swagger_validator
            }
        }},
        {events_fetch_limit, 32}
    ]);

start_app(AppName) ->
    [genlib_app:start_application(AppName)].

-spec start_app(app_name(), list()) ->
    [app_name()].

start_app(AppName, Env) ->
    genlib_app:start_application_with(AppName, Env).

-spec start_app_with(app_name(), app_env()) -> [app_name()].

start_app_with(AppName, Env) ->
    _ = application:load(AppName),
    _ = set_app_env(AppName, Env),
    case application:ensure_all_started(AppName) of
        {ok, Apps} ->
            Apps;
        {error, Reason} ->
            exit({start_app_failed, AppName, Reason})
    end.

set_app_env(AppName, Env) ->
    lists:foreach(
        fun ({K, V}) ->
            ok = application:set_env(AppName, K, V)
        end,
        Env
    ).

-spec get_keysource(_, config()) ->
    _.

get_keysource(Key, Config) ->
    filename:join(?config(data_dir, Config), Key).

-spec issue_token(_, _, _, _) -> % TODO: spec
    {ok, binary()} |
    {error,
        nonexistent_signee
    }.

issue_token(PartyID, ACL, LifeTime, Domain) ->
    Claims = #{
        <<"exp">> => LifeTime,
        <<"resource_access">> =>#{
            Domain => uac_acl:from_list(ACL)
        }
    },
    uac_authorizer_jwt:issue(
        wapi_utils:get_unique_id(),
        PartyID,
        Claims,
        ?SIGNEE
    ).

-spec get_context(binary()) ->
    wapi_client_lib:context().

get_context(Token) ->
    wapi_client_lib:get_context(?WAPI_URL, Token, 10000, ipv4).

% TODO move it to `wapi_dummy_service`, looks more appropriate

-spec start_mocked_service_sup(module()) ->
    pid().

start_mocked_service_sup(Module) ->
    {ok, SupPid} = supervisor:start_link(Module, []),
    _ = unlink(SupPid),
    SupPid.

-spec stop_mocked_service_sup(pid()) ->
    _.

stop_mocked_service_sup(SupPid) ->
    exit(SupPid, shutdown).

-spec mock_services(_, _) ->
    _.

mock_services(Services, SupOrConfig) ->
    maps:map(fun start_woody_client/2, mock_services_(Services, SupOrConfig)).

start_woody_client(bender_thrift, Urls) ->
    ok = application:set_env(
        bender_client,
        services,
        Urls
    ),
    start_app(bender_client, []);
start_woody_client(wapi, Urls) ->
    ok = application:set_env(
        wapi_woody_client,
        service_urls,
        Urls
    ),
    start_app(wapi_woody_client, []).

-spec mock_services_(_, _) ->
    _.

% TODO need a better name
mock_services_(Services, Config) when is_list(Config) ->
    mock_services_(Services, ?config(test_sup, Config));

mock_services_(Services, SupPid) when is_pid(SupPid) ->
    Name = lists:map(fun get_service_name/1, Services),

    Port = get_random_port(),
    {ok, IP} = inet:parse_address(?WAPI_IP),
    ChildSpec = woody_server:child_spec(
        {dummy, Name},
        #{
            ip => IP,
            port => Port,
            event_handler => scoper_woody_event_handler,
            handlers => lists:map(fun mock_service_handler/1, Services)
        }
    ),
    {ok, _} = supervisor:start_child(SupPid, ChildSpec),

    lists:foldl(
        fun (Service, Acc) ->
            ServiceName = get_service_name(Service),
            case ServiceName of
                bender_thrift ->
                    Acc#{ServiceName => #{'Bender' => make_url(ServiceName, Port)}};
                _ ->
                    WapiWoodyClient = maps:get(wapi, Acc, #{}),
                    Acc#{wapi => WapiWoodyClient#{ServiceName => make_url(ServiceName, Port)}}
            end
        end,
        #{},
        Services
    ).

get_service_name({ServiceName, _Fun}) ->
    ServiceName;
get_service_name({ServiceName, _WoodyService, _Fun}) ->
    ServiceName.

mock_service_handler({ServiceName = bender_thrift, Fun}) ->
    mock_service_handler(ServiceName, {bender_thrift, 'Bender'}, Fun);
mock_service_handler({ServiceName, Fun}) ->
    mock_service_handler(ServiceName, wapi_woody_client:get_service_modname(ServiceName), Fun);
mock_service_handler({ServiceName, WoodyService, Fun}) ->
    mock_service_handler(ServiceName, WoodyService, Fun).

mock_service_handler(ServiceName, WoodyService, Fun) ->
    {make_path(ServiceName), {WoodyService, {wapi_dummy_service, #{function => Fun}}}}.

% TODO not so failproof, ideally we need to bind socket first and then give to a ranch listener
get_random_port() ->
    rand:uniform(32768) + 32767.

make_url(ServiceName, Port) ->
    iolist_to_binary(["http://", ?WAPI_HOST_NAME, ":", integer_to_list(Port), make_path(ServiceName)]).

make_path(ServiceName) ->
    "/" ++ atom_to_list(ServiceName).

-spec get_lifetime() ->
    map().

get_lifetime() ->
    get_lifetime(0, 0, 7).

get_lifetime(YY, MM, DD) ->
    #{
       <<"years">>  => YY,
       <<"months">> => MM,
       <<"days">>   => DD
    }.

-spec create_auth_ctx(ff_party:id()) ->
    wapi_handler:context().

create_auth_ctx(PartyID) ->
    #{
        swagger_context => #{auth_context => {?STRING, PartyID, #{}}}
    }.
