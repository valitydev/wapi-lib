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
    CurrencyRef = #domain_CurrencyRef{symbolic_code = <<"RUB">>},
    Version = ?INTEGER,
    WalletConfigObject = mk_wallet_config(?STRING, 1),
    %% Wallet configs for cash limits scenarios (each -> different PI)
    WalletConfigLimitsOk = mk_wallet_config(?WALLET_ID_OK, 1),
    WalletConfigCandidateDisabled = mk_wallet_config(?WALLET_ID_CANDIDATE_DISABLED, 2),
    WalletConfigPrimaryDisabled = mk_wallet_config(?WALLET_ID_PRIMARY_DISABLED, 5),
    PartyConfigObject = #domain_PartyConfigObject{
        ref = #domain_PartyConfigRef{id = ?STRING},
        data = #domain_PartyConfig{
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
            contact_info = #domain_PartyContactInfo{
                registration_email = <<"test@test.ru">>
            }
        }
    },
    %% Term set hierarchy (shared)
    WithdrawalLimitRange = #domain_CashRange{
        lower = {inclusive, #domain_Cash{amount = 100, currency = CurrencyRef}},
        upper = {inclusive, #domain_Cash{amount = 500, currency = CurrencyRef}}
    },
    PaymentMethods = [
        #domain_PaymentMethodRef{id = {bank_card, #domain_BankCardPaymentMethod{}}},
        #domain_PaymentMethodRef{id = {digital_wallet, #domain_PaymentServiceRef{id = <<"DW">>}}}
    ],
    TermSetHierarchyObject = #domain_TermSetHierarchyObject{
        ref = #domain_TermSetHierarchyRef{id = 1},
        data = #domain_TermSetHierarchy{
            term_set = #domain_TermSet{
                wallets = #domain_WalletServiceTerms{
                    withdrawals = #domain_WithdrawalServiceTerms{
                        methods = {value, PaymentMethods},
                        cash_limit = {value, WithdrawalLimitRange}
                    }
                }
            }
        }
    },
    Term10Limit = #domain_CashRange{
        lower = {inclusive, #domain_Cash{amount = 200, currency = CurrencyRef}},
        upper = {inclusive, #domain_Cash{amount = 900, currency = CurrencyRef}}
    },
    Term20Limit = #domain_CashRange{
        lower = {inclusive, #domain_Cash{amount = 300, currency = CurrencyRef}},
        upper = {inclusive, #domain_Cash{amount = 800, currency = CurrencyRef}}
    },
    Allowed = {constant, true},
    Disallowed = {constant, false},
    Terminal10 = mk_terminal_object(10, 11, Term10Limit, Allowed, Allowed),
    Terminal20 = mk_terminal_object(20, 21, Term20Limit, Allowed, Allowed),
    Provider11 = mk_provider_object(11, Allowed, Allowed),
    Provider21 = mk_provider_object(21, Allowed, Allowed),

    Routing100 = #domain_RoutingRuleset{
        name = <<"both">>,
        decisions =
            {candidates, [
                #domain_RoutingCandidate{allowed = Allowed, terminal = #domain_TerminalRef{id = 10}},
                #domain_RoutingCandidate{allowed = Allowed, terminal = #domain_TerminalRef{id = 20}}
            ]}
    },
    Routing101 = #domain_RoutingRuleset{
        name = <<"none">>,
        decisions =
            {candidates, [
                #domain_RoutingCandidate{allowed = Disallowed, terminal = #domain_TerminalRef{id = 10}},
                #domain_RoutingCandidate{allowed = Disallowed, terminal = #domain_TerminalRef{id = 20}}
            ]}
    },
    Routing103 = #domain_RoutingRuleset{
        name = <<"term20">>,
        decisions =
            {candidates, [
                #domain_RoutingCandidate{allowed = Disallowed, terminal = #domain_TerminalRef{id = 10}},
                #domain_RoutingCandidate{allowed = Allowed, terminal = #domain_TerminalRef{id = 20}}
            ]}
    },
    RoutingRules = #{
        100 => Routing100,
        101 => Routing101,
        103 => Routing103
    },
    RoutingRulesObjects = [
        #domain_RoutingRulesObject{ref = #domain_RoutingRulesetRef{id = Id}, data = Data}
     || {Id, Data} <- maps:to_list(RoutingRules)
    ],

    ProhibitionsId = 101,
    PiObjects = [
        mk_pi_object(1, 100, ProhibitionsId),
        mk_pi_object(2, 101, ProhibitionsId),
        mk_pi_object(5, 103, ProhibitionsId)
    ],
    PiMap = maps:from_list([
        {(P#domain_PaymentInstitutionObject.ref)#domain_PaymentInstitutionRef.id, P}
     || P <- PiObjects
    ]),
    RoutingMap = maps:from_list([
        {(R#domain_RoutingRulesObject.ref)#domain_RoutingRulesetRef.id, R}
     || R <- RoutingRulesObjects
    ]),
    DomainConfigClient = fun
        ('CheckoutObject', {{version, ?INTEGER}, {wallet_config, #domain_WalletConfigRef{id = ?STRING}}}) ->
            {ok, mk_versioned_object(wallet_config, WalletConfigObject, Version)};
        ('CheckoutObject', {{version, ?INTEGER}, {wallet_config, #domain_WalletConfigRef{id = ?WALLET_ID_OK}}}) ->
            {ok, mk_versioned_object(wallet_config, WalletConfigLimitsOk, Version)};
        (
            'CheckoutObject',
            {{version, ?INTEGER}, {wallet_config, #domain_WalletConfigRef{id = ?WALLET_ID_CANDIDATE_DISABLED}}}
        ) ->
            {ok, mk_versioned_object(wallet_config, WalletConfigCandidateDisabled, Version)};
        (
            'CheckoutObject',
            {{version, ?INTEGER}, {wallet_config, #domain_WalletConfigRef{id = ?WALLET_ID_PRIMARY_DISABLED}}}
        ) ->
            {ok, mk_versioned_object(wallet_config, WalletConfigPrimaryDisabled, Version)};
        ('CheckoutObject', {{version, ?INTEGER}, {party_config, #domain_PartyConfigRef{id = ?STRING}}}) ->
            {ok, mk_versioned_object(party_config, PartyConfigObject, Version)};
        ('CheckoutObject', {{version, ?INTEGER}, {term_set_hierarchy, #domain_TermSetHierarchyRef{id = 1}}}) ->
            {ok, mk_versioned_object(term_set_hierarchy, TermSetHierarchyObject, Version)};
        ('CheckoutObject', {{version, ?INTEGER}, {payment_institution, #domain_PaymentInstitutionRef{id = 1}}}) ->
            {ok, mk_versioned_object(payment_institution, maps:get(1, PiMap), Version)};
        ('CheckoutObject', {{version, ?INTEGER}, {payment_institution, #domain_PaymentInstitutionRef{id = 2}}}) ->
            {ok, mk_versioned_object(payment_institution, maps:get(2, PiMap), Version)};
        ('CheckoutObject', {{version, ?INTEGER}, {payment_institution, #domain_PaymentInstitutionRef{id = 5}}}) ->
            {ok, mk_versioned_object(payment_institution, maps:get(5, PiMap), Version)};
        ('CheckoutObject', {{version, ?INTEGER}, {routing_rules, #domain_RoutingRulesetRef{id = 100}}}) ->
            {ok, mk_versioned_object(routing_rules, maps:get(100, RoutingMap), Version)};
        ('CheckoutObject', {{version, ?INTEGER}, {routing_rules, #domain_RoutingRulesetRef{id = 101}}}) ->
            {ok, mk_versioned_object(routing_rules, maps:get(101, RoutingMap), Version)};
        ('CheckoutObject', {{version, ?INTEGER}, {routing_rules, #domain_RoutingRulesetRef{id = 103}}}) ->
            {ok, mk_versioned_object(routing_rules, maps:get(103, RoutingMap), Version)};
        ('CheckoutObject', {{version, ?INTEGER}, {terminal, #domain_TerminalRef{id = 10}}}) ->
            {ok, mk_versioned_object(terminal, Terminal10, Version)};
        ('CheckoutObject', {{version, ?INTEGER}, {terminal, #domain_TerminalRef{id = 20}}}) ->
            {ok, mk_versioned_object(terminal, Terminal20, Version)};
        ('CheckoutObject', {{version, ?INTEGER}, {provider, #domain_ProviderRef{id = 11}}}) ->
            {ok, mk_versioned_object(provider, Provider11, Version)};
        ('CheckoutObject', {{version, ?INTEGER}, {provider, #domain_ProviderRef{id = 21}}}) ->
            {ok, mk_versioned_object(provider, Provider21, Version)};
        ('CheckoutObject', _) ->
            woody_error:raise(business, #domain_conf_v2_ObjectNotFound{})
    end,
    Urls = mock_services_(
        [
            {domain_config_client, DomainConfigClient},
            {domain_config, fun('GetLatestVersion', _) -> {ok, Version} end}
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
    Existing =
        case application:get_env(wapi_lib, service_urls) of
            {ok, M} when is_map(M) -> M;
            _ -> #{}
        end,
    ok = application:set_env(
        wapi_lib,
        service_urls,
        maps:merge(Existing, Urls)
    );
start_woody_client(domain_config, Url) ->
    update_dmt_service_url('Repository', Url);
start_woody_client(domain_config_client, Url) ->
    update_dmt_service_url('RepositoryClient', Url).

update_dmt_service_url(Key, Url) ->
    ServiceUrls =
        case application:get_env(dmt_client, service_urls) of
            {ok, Urls} -> Urls;
            undefined -> #{}
        end,
    ok = application:set_env(dmt_client, service_urls, ServiceUrls#{Key => Url}).

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
mock_service_handler({ServiceName = party_management, Fun}) ->
    mock_service_handler(ServiceName, {dmsl_payproc_thrift, 'PartyManagement'}, Fun);
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

mk_versioned_object(Type, Object, Version) ->
    #domain_conf_v2_VersionedObject{
        info = #domain_conf_v2_VersionedObjectInfo{
            version = Version,
            changed_at = genlib_rfc3339:format(genlib_time:unow(), second),
            changed_by = #domain_conf_v2_Author{
                id = ?STRING,
                name = ?STRING,
                email = ?STRING
            }
        },
        object = {Type, Object}
    }.

%% Terminal helper: TerminalRefId, ProviderRefId, CashLimitRange, Allow, GlobalAllow
mk_terminal_object(TermId, ProvId, LimitRange, Allow, GlobalAllow) ->
    #domain_TerminalObject{
        ref = #domain_TerminalRef{id = TermId},
        data = #domain_Terminal{
            name = <<"term">>,
            description = <<"test">>,
            provider_ref = #domain_ProviderRef{id = ProvId},
            terms = #domain_ProvisionTermSet{
                wallet = #domain_WalletProvisionTerms{
                    withdrawals = #domain_WithdrawalProvisionTerms{
                        cash_limit = {value, LimitRange},
                        allow = Allow,
                        global_allow = GlobalAllow
                    }
                }
            }
        }
    }.

%% Payment institution helper: PiRefId, PoliciesRulesetId, ProhibitionsRulesetId
mk_pi_object(PiId, PoliciesId, ProhibitionsId) ->
    #domain_PaymentInstitutionObject{
        ref = #domain_PaymentInstitutionRef{id = PiId},
        data = #domain_PaymentInstitution{
            name = <<"test">>,
            system_account_set = {value, #domain_SystemAccountSetRef{id = 1}},
            inspector = {value, #domain_InspectorRef{id = 1}},
            realm = test,
            residences = [rus],
            withdrawal_routing_rules = #domain_RoutingRules{
                policies = #domain_RoutingRulesetRef{id = PoliciesId},
                prohibitions = #domain_RoutingRulesetRef{id = ProhibitionsId}
            }
        }
    }.

%% Wallet config helper: WalletConfigRefId, PaymentInstitutionId
mk_wallet_config(WalletRefId, PiId) ->
    #domain_WalletConfigObject{
        ref = #domain_WalletConfigRef{id = WalletRefId},
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
            payment_institution = #domain_PaymentInstitutionRef{id = PiId},
            terms = #domain_TermSetHierarchyRef{id = 1},
            account = #domain_WalletAccount{
                currency = #domain_CurrencyRef{symbolic_code = <<"RUB">>},
                settlement = ?INTEGER
            },
            party_ref = #domain_PartyConfigRef{id = ?STRING}
        }
    }.

%% Provider helper: ProviderRefId, Allow, GlobalAllow
mk_provider_object(ProvId, Allow, GlobalAllow) ->
    #domain_ProviderObject{
        ref = #domain_ProviderRef{id = ProvId},
        data = #domain_Provider{
            name = <<"provider">>,
            description = <<"test">>,
            proxy = #domain_Proxy{
                ref = #domain_ProxyRef{id = 1},
                additional = #{}
            },
            realm = test,
            terms = #domain_ProvisionTermSet{
                wallet = #domain_WalletProvisionTerms{
                    withdrawals = #domain_WithdrawalProvisionTerms{
                        allow = Allow,
                        global_allow = GlobalAllow
                    }
                }
            }
        }
    }.
