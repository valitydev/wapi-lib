-module(wapi_ct_helper).

-include_lib("common_test/include/ct.hrl").
-include_lib("damsel/include/dmsl_domain_conf_v2_thrift.hrl").
-include_lib("damsel/include/dmsl_domain_thrift.hrl").
-include_lib("wapi_wallet_dummy_data.hrl").
-include_lib("wapi_token_keeper_data.hrl").

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
-export([get_context/1]).
-export([get_keysource/2]).
-export([start_mocked_service_sup/2]).
-export([start_mocked_service_sup/1]).
-export([stop_mocked_service_sup/1]).
-export([mock_services/2]).
-export([mock_services_/2]).
-export([get_lifetime/0]).
-export([create_auth_ctx/1]).

-define(WAPI_IP, "::").
-define(WAPI_PORT, 8080).
-define(WAPI_HOST_NAME, "localhost").
-define(WAPI_URL, ?WAPI_HOST_NAME ++ ":" ++ integer_to_list(?WAPI_PORT)).

%%
-type config() :: [{atom(), any()}].
-type test_case_name() :: atom().
-type app_name() :: atom().
-type app_env() :: [{atom(), term()}].
-type sup_or_config() :: config() | pid().

-export_type([config/0]).
-export_type([app_name/0]).
-export_type([sup_or_config/0]).

-define(SIGNEE, wapi_lib).

-spec cfg(atom(), config()) -> term().
cfg(Key, Config) ->
    case lists:keyfind(Key, 1, Config) of
        {Key, V} -> V;
        _ -> error({'ct config entry missing', Key})
    end.

-spec cfg(atom(), _, config()) -> config().
cfg(Key, Value, Config) ->
    lists:keystore(Key, 1, Config, {Key, Value}).

-type config_mut_fun() :: fun((config()) -> config()).

-spec makeup_cfg([config_mut_fun()], config()) -> config().
makeup_cfg(CMFs, C0) ->
    lists:foldl(fun(CMF, C) -> CMF(C) end, C0, CMFs).

-spec woody_ctx() -> config_mut_fun().
woody_ctx() ->
    fun(C) -> cfg('$woody_ctx', construct_woody_ctx(C), C) end.

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
    fun(C) -> cfg('$test_case_name', TestCaseName, C) end.

-spec get_test_case_name(config()) -> test_case_name().
get_test_case_name(C) ->
    cfg('$test_case_name', C).

%

-spec init_suite(module(), config()) -> config().
init_suite(Module, Config) ->
    SupPid = start_mocked_service_sup(Module),
    Apps1 =
        start_app(scoper) ++
            start_app(woody) ++
            start_app({dmt_client, SupPid}) ++
            start_app({wapi_lib, Config}),
    {ok, _} = supervisor:start_child(
        SupPid, wapi_ct_helper_swagger_server:child_spec(#{wallet => {wapi_ct_helper_handler, #{}}})
    ),
    UacConfig = maps:merge(
        #{
            jwt => #{
                keyset => #{
                    wapi_lib => #{
                        source => {pem_file, get_keysource("private.pem", Config)},
                        metadata => #{
                            auth_method => user_session_token,
                            user_realm => <<"external">>
                        }
                    }
                }
            }
        },
        #{access => wapi_tokens_legacy:get_access_config()}
    ),
    ok = uac:configure(UacConfig),
    _ = wapi_ct_helper_bouncer:mock_client(SupPid),
    [{apps, lists:reverse(Apps1)}, {suite_test_sup, SupPid} | Config].

-spec start_app(app_name() | {app_name(), _Config}) -> [app_name()].
start_app(scoper = AppName) ->
    start_app_with(AppName, [
        {storage, scoper_storage_logger}
    ]);
start_app(woody = AppName) ->
    start_app_with(AppName, [
        {acceptors_pool_size, 4}
    ]);
start_app({dmt_client = AppName, SupPid}) ->
    WalletConfig = #domain_WalletConfig{
        id = ?STRING,
        created_at = wapi_time:rfc3339(),
        blocking =
            {unblocked, #domain_Unblocked{
                reason = <<"">>,
                since = wapi_time:rfc3339()
            }},
        suspension =
            {active, #domain_Active{
                since = wapi_time:rfc3339()
            }},
        details = #domain_Details{
            name = <<"Test Wallet">>,
            description = <<"Test description">>
        },
        currency_configs = #{
            #domain_CurrencyRef{symbolic_code = <<"RUB">>} => #domain_WalletCurrencyConfig{
                currency = #domain_CurrencyRef{symbolic_code = <<"RUB">>},
                settlement = ?INTEGER
            }
        },
        payment_institution = #domain_PaymentInstitutionRef{id = 1},
        terms = #domain_TermSetHierarchyRef{id = 1},
        party_id = ?STRING
    },
    WalletConfigObject = #domain_WalletConfigObject{ref = #domain_WalletConfigRef{id = ?STRING}, data = WalletConfig},
    PartyConfig = #domain_PartyConfig{
        id = ?STRING,
        contact_info = #domain_PartyContactInfo{
            registration_email = <<"test@test.ru">>
        },
        created_at = wapi_time:rfc3339(),
        blocking =
            {unblocked, #domain_Unblocked{
                reason = <<"">>,
                since = wapi_time:rfc3339()
            }},
        suspension =
            {active, #domain_Active{
                since = wapi_time:rfc3339()
            }},
        shops = [],
        wallets = [#domain_WalletConfigRef{id = ?STRING}]
    },
    PartyConfigObject = #domain_PartyConfigObject{ref = #domain_PartyConfigRef{id = ?STRING}, data = PartyConfig},
    Urls = mock_services_(
        [
            {domain_config_client, fun
                ('CheckoutObject', {{version, ?INTEGER}, {wallet_config, #domain_WalletConfigRef{id = ?STRING}}}) ->
                    {ok, #domain_conf_v2_VersionedObject{
                        info = #domain_conf_v2_VersionedObjectInfo{
                            version = ?INTEGER,
                            changed_at = genlib_rfc3339:format(genlib_time:unow(), second),
                            changed_by = #domain_conf_v2_Author{
                                id = ?STRING,
                                name = ?STRING,
                                email = ?STRING
                            }
                        },
                        object = {wallet_config, WalletConfigObject}
                    }};
                ('CheckoutObject', {{version, ?INTEGER}, {party_config, #domain_PartyConfigRef{id = ?STRING}}}) ->
                    {ok, #domain_conf_v2_VersionedObject{
                        info = #domain_conf_v2_VersionedObjectInfo{
                            version = ?INTEGER,
                            changed_at = genlib_rfc3339:format(genlib_time:unow(), second),
                            changed_by = #domain_conf_v2_Author{
                                id = ?STRING,
                                name = ?STRING,
                                email = ?STRING
                            }
                        },
                        object = {party_config, PartyConfigObject}
                    }};
                ('CheckoutObject', _) ->
                    woody_error:raise(business, #domain_conf_v2_ObjectNotFound{})
            end},
            {domain_config, fun('GetLatestVersion', _) ->
                {ok, ?INTEGER}
            end}
        ],
        SupPid
    ),
    start_app_with(AppName, [
        {service_urls, #{
            'Repository' => maps:get(domain_config, Urls),
            'RepositoryClient' => maps:get(domain_config_client, Urls)
        }}
    ]);
start_app({wapi_lib = AppName, Config}) ->
    start_app_with(AppName, [
        {ip, ?WAPI_IP},
        {port, ?WAPI_PORT},
        {realm, <<"external">>},
        {public_endpoint, <<"localhost:8080">>},
        {bouncer_ruleset_id, ?TEST_RULESET_ID},
        {signee, ?SIGNEE},
        {lechiffre_opts, #{
            encryption_source => {json, {file, get_keysource("jwk.publ.json", Config)}},
            decryption_sources => [
                {json, {file, get_keysource("jwk.priv.json", Config)}}
            ]
        }},
        {events_fetch_limit, 32},
        {auth_config, #{
            metadata_mappings => #{
                party_id => ?TK_META_PARTY_ID,
                user_id => ?TK_META_USER_ID,
                user_email => ?TK_META_USER_EMAIL
            }
        }}
    ]);
start_app(AppName) ->
    [genlib_app:start_application(AppName)].

-spec start_app(app_name(), list()) -> [app_name()].
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
        fun({K, V}) ->
            ok = application:set_env(AppName, K, V)
        end,
        Env
    ).

-spec get_keysource(_, config()) -> _.
get_keysource(Key, Config) ->
    filename:join(?config(data_dir, Config), Key).

-spec get_context(binary()) -> wapi_client_lib:context().
get_context(Token) ->
    wapi_client_lib:get_context(?WAPI_URL, Token, 10000, ipv4).

% TODO move it to `wapi_dummy_service`, looks more appropriate

-spec start_mocked_service_sup(module()) -> pid().
start_mocked_service_sup(Module) ->
    start_mocked_service_sup(Module, []).

-spec start_mocked_service_sup(module(), term()) -> pid().
start_mocked_service_sup(Module, Args) ->
    {ok, SupPid} = supervisor:start_link(Module, Args),
    _ = unlink(SupPid),
    SupPid.

-spec stop_mocked_service_sup(pid()) -> _.
stop_mocked_service_sup(SupPid) ->
    exit(SupPid, kill).

-spec mock_services(_, _) -> _.
mock_services(Services, SupOrConfig) ->
    maps:map(fun start_woody_client/2, mock_services_(Services, SupOrConfig)).

start_woody_client(bender, Urls) ->
    ok = application:set_env(
        bender_client,
        services,
        Urls
    ),
    start_app(bender_client, []);
start_woody_client(wapi_lib, Urls) ->
    ok = application:set_env(
        wapi_lib,
        service_urls,
        Urls
    ).

-spec mock_services_(_, _) -> _.
% TODO need a better name
mock_services_(Services, Config) when is_list(Config) ->
    mock_services_(Services, ?config(test_sup, Config));
mock_services_(Services, SupPid) when is_pid(SupPid) ->
    Name = lists:map(fun get_service_name/1, Services),
    {ok, IP} = inet:parse_address(?WAPI_IP),
    ServerID = {dummy, Name},
    WoodyOpts = #{
        ip => IP,
        port => 0,
        event_handler => scoper_woody_event_handler,
        handlers => lists:map(fun mock_service_handler/1, Services)
    },
    ChildSpec = woody_server:child_spec(ServerID, WoodyOpts),
    {ok, _} = supervisor:start_child(SupPid, ChildSpec),
    {_IP, Port} = woody_server:get_addr(ServerID, WoodyOpts),
    lists:foldl(
        fun(Service, Acc) ->
            ServiceName = get_service_name(Service),
            case ServiceName of
                bouncer ->
                    Acc#{ServiceName => make_url(ServiceName, Port)};
                org_management ->
                    Acc#{ServiceName => make_url(ServiceName, Port)};
                token_authenticator ->
                    Acc#{ServiceName => make_url(ServiceName, Port)};
                bender ->
                    Acc#{ServiceName => #{'Bender' => make_url(ServiceName, Port)}};
                domain_config ->
                    Acc#{ServiceName => make_url(ServiceName, Port)};
                domain_config_client ->
                    Acc#{ServiceName => make_url(ServiceName, Port)};
                _ ->
                    WapiWoodyClient = maps:get(wapi_lib, Acc, #{}),
                    Acc#{wapi_lib => WapiWoodyClient#{ServiceName => make_url(ServiceName, Port)}}
            end
        end,
        #{},
        Services
    ).

get_service_name({ServiceName, _Fun}) ->
    ServiceName;
get_service_name({ServiceName, _WoodyService, _Fun}) ->
    ServiceName.

mock_service_handler({ServiceName = bender, Fun}) ->
    mock_service_handler(ServiceName, {bender_bender_thrift, 'Bender'}, Fun);
mock_service_handler({ServiceName = token_authenticator, Fun}) ->
    mock_service_handler(ServiceName, {tk_token_keeper_thrift, 'TokenAuthenticator'}, Fun);
mock_service_handler({ServiceName = bouncer, Fun}) ->
    mock_service_handler(ServiceName, {bouncer_decision_thrift, 'Arbiter'}, Fun);
mock_service_handler({ServiceName = org_management, Fun}) ->
    mock_service_handler(ServiceName, {orgmgmt_authctx_provider_thrift, 'AuthContextProvider'}, Fun);
mock_service_handler({ServiceName = domain_config, Fun}) ->
    mock_service_handler(ServiceName, {dmsl_domain_conf_v2_thrift, 'Repository'}, Fun);
mock_service_handler({ServiceName = domain_config_client, Fun}) ->
    mock_service_handler(ServiceName, {dmsl_domain_conf_v2_thrift, 'RepositoryClient'}, Fun);
mock_service_handler({ServiceName, Fun}) ->
    mock_service_handler(ServiceName, wapi_woody_client:get_service_modname(ServiceName), Fun);
mock_service_handler({ServiceName, WoodyService, Fun}) ->
    mock_service_handler(ServiceName, WoodyService, Fun).

mock_service_handler(ServiceName, WoodyService, Fun) ->
    {make_path(ServiceName), {WoodyService, {wapi_dummy_service, #{function => Fun}}}}.

make_url(ServiceName, Port) ->
    iolist_to_binary(["http://", ?WAPI_HOST_NAME, ":", integer_to_list(Port), make_path(ServiceName)]).

make_path(ServiceName) ->
    "/" ++ atom_to_list(ServiceName).

-spec get_lifetime() -> map().
get_lifetime() ->
    get_lifetime(0, 0, 7).

get_lifetime(YY, MM, DD) ->
    #{
        <<"years">> => YY,
        <<"months">> => MM,
        <<"days">> => DD
    }.

-spec create_auth_ctx(binary()) -> #{swagger_context => wapi_wallet_handler:request_context()}.
create_auth_ctx(PartyID) ->
    #{
        swagger_context => #{auth_context => {?STRING, PartyID, #{}}}
    }.
