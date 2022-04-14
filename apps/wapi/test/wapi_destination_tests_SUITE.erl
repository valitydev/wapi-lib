-module(wapi_destination_tests_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").

-include_lib("wapi_wallet_dummy_data.hrl").

-include_lib("fistful_proto/include/ff_proto_destination_thrift.hrl").
-include_lib("tds_proto/include/tds_storage_thrift.hrl").

-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([end_per_suite/1]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([init/1]).

-export([create_extension_destination_ok_test/1]).
-export([create_extension_destination_fail_unknown_resource_test/1]).
-export([create_destination_ok_test/1]).
-export([create_destination_fail_resource_token_invalid_test/1]).
-export([create_destination_fail_resource_token_expire_test/1]).
-export([create_destination_fail_identity_notfound_test/1]).
-export([create_destination_fail_currency_notfound_test/1]).
-export([create_destination_fail_party_inaccessible_test/1]).
-export([create_destination_fail_withdrawal_method_test/1]).
-export([get_destination_ok_test/1]).
-export([get_destination_fail_notfound_test/1]).
-export([bank_card_resource_test/1]).
-export([bitcoin_resource_test/1]).
-export([litecoin_resource_test/1]).
-export([bitcoin_cash_resource_test/1]).
-export([ripple_resource_test/1]).
-export([ethereum_resource_test/1]).
-export([usdt_resource_test/1]).
-export([zcash_resource_test/1]).
-export([digital_wallet_resource_test/1]).
-export([digital_wallet_w_token_resource_test/1]).

% common-api is used since it is the domain used in production RN
% TODO: change to wallet-api (or just omit since it is the default one) when new tokens will be a thing
-define(DOMAIN, <<"common-api">>).
-define(GENERIC_RESOURCE_TYPE, <<"BankTransferGeneric">>).
-define(GENERIC_RESOURCE_NAME, <<"GenericBankAccount">>).

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
            create_extension_destination_ok_test,
            create_extension_destination_fail_unknown_resource_test,
            create_destination_ok_test,
            create_destination_fail_resource_token_invalid_test,
            create_destination_fail_resource_token_expire_test,
            create_destination_fail_identity_notfound_test,
            create_destination_fail_currency_notfound_test,
            create_destination_fail_party_inaccessible_test,
            create_destination_fail_withdrawal_method_test,
            get_destination_ok_test,
            get_destination_fail_notfound_test,
            bank_card_resource_test,
            bitcoin_resource_test,
            litecoin_resource_test,
            bitcoin_cash_resource_test,
            ripple_resource_test,
            ethereum_resource_test,
            usdt_resource_test,
            zcash_resource_test,
            digital_wallet_resource_test,
            digital_wallet_w_token_resource_test
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
init_per_testcase(Name, C) when
    Name =:= create_extension_destination_ok_test orelse
        Name =:= create_extension_destination_fail_unknown_resource_test
->
    meck:new(swag_server_wallet_schema, [no_link, passthrough]),
    meck:new(swag_client_wallet_schema, [no_link, passthrough]),
    makeup_and_start_mock_per_testcase(Name, C);
init_per_testcase(Name, C) ->
    makeup_and_start_mock_per_testcase(Name, C).

-spec end_per_testcase(test_case_name(), config()) -> ok.
end_per_testcase(Name, C) when
    Name =:= create_extension_destination_ok_test orelse
        Name =:= create_extension_destination_fail_unknown_resource_test
->
    meck:unload(swag_server_wallet_schema),
    meck:unload(swag_client_wallet_schema),
    end_mock_per_testcase(C);
end_per_testcase(_Name, C) ->
    end_mock_per_testcase(C).

makeup_and_start_mock_per_testcase(Name, C) ->
    C1 = wapi_ct_helper:makeup_cfg([wapi_ct_helper:test_case_name(Name), wapi_ct_helper:woody_ctx()], C),
    [{test_sup, wapi_ct_helper:start_mocked_service_sup(?MODULE)} | C1].

end_mock_per_testcase(C) ->
    wapi_ct_helper:stop_mocked_service_sup(?config(test_sup, C)),
    ok.

%%% Tests

-spec create_extension_destination_ok_test(config()) -> _.
create_extension_destination_ok_test(C) ->
    Ref = <<"#/definitions/", ?GENERIC_RESOURCE_NAME/binary>>,
    ResourceSchema = #{
        <<"allOf">> =>
            [
                #{
                    <<"$ref">> => <<"#/definitions/DestinationResource">>
                },
                #{
                    <<"$ref">> => Ref
                }
            ],
        <<"x-vality-genericMethod">> =>
            #{
                <<"schema">> =>
                    #{
                        <<"id">> => <<"https://some.link">>,
                        <<"allOf">> =>
                            [
                                #{
                                    <<"$ref">> => Ref
                                }
                            ]
                    }
            }
    },
    mock_generic_schema(ResourceSchema),
    Destination = make_destination(C, generic),
    _ = create_destination_start_mocks(C, {ok, Destination}),
    ?assertMatch(
        {ok, _},
        create_destination_call_api(C, Destination)
    ).

-spec create_extension_destination_fail_unknown_resource_test(config()) -> _.
create_extension_destination_fail_unknown_resource_test(C) ->
    Ref = <<"#/definitions/", ?GENERIC_RESOURCE_NAME/binary>>,
    ResourceSchema = #{
        <<"allOf">> => [
            #{
                <<"$ref">> => <<"#/definitions/DestinationResource">>
            },
            #{
                <<"$ref">> => Ref
            }
        ]
    },
    mock_generic_schema(ResourceSchema),
    Destination = make_destination(C, generic),
    _ = create_destination_start_mocks(C, {ok, Destination}),
    ?assertMatch(
        {error,
            {400, #{
                <<"errorType">> := <<"SchemaViolated">>,
                <<"description">> := <<"Unknown resource">>
            }}},
        create_destination_call_api(C, Destination)
    ).

-spec create_destination_ok_test(config()) -> _.
create_destination_ok_test(C) ->
    Destination = make_destination(C, bank_card),
    _ = create_destination_start_mocks(C, {ok, Destination}),
    ?assertMatch(
        {ok, _},
        create_destination_call_api(C, Destination)
    ).

-spec create_destination_fail_resource_token_invalid_test(config()) -> _.
create_destination_fail_resource_token_invalid_test(C) ->
    Destination = make_destination(C, bank_card),
    _ = create_destination_start_mocks(C, {ok, Destination}),
    ?assertMatch(
        {error,
            {400, #{
                <<"errorType">> := <<"InvalidResourceToken">>,
                <<"name">> := <<"BankCardDestinationResource">>
            }}},
        create_destination_call_api(C, Destination, <<"v1.InvalidResourceToken">>)
    ).

-spec create_destination_fail_resource_token_expire_test(config()) -> _.
create_destination_fail_resource_token_expire_test(C) ->
    ExpiredDeadline = wapi_utils:deadline_from_timeout(0),
    InvalidResourceToken = wapi_crypto:create_resource_token({bank_card, ?BANK_CARD}, ExpiredDeadline),
    Destination = make_destination(C, bank_card),
    _ = create_destination_start_mocks(C, {ok, Destination}),
    ?assertMatch(
        {error,
            {400, #{
                <<"errorType">> := <<"InvalidResourceToken">>,
                <<"name">> := <<"BankCardDestinationResource">>
            }}},
        create_destination_call_api(C, Destination, InvalidResourceToken)
    ).

-spec create_destination_fail_identity_notfound_test(config()) -> _.
create_destination_fail_identity_notfound_test(C) ->
    Destination = make_destination(C, bank_card),
    _ = create_destination_start_mocks(C, {throwing, #fistful_IdentityNotFound{}}),
    ?assertEqual(
        {error, {422, #{<<"message">> => <<"No such identity">>}}},
        create_destination_call_api(C, Destination)
    ).

-spec create_destination_fail_currency_notfound_test(config()) -> _.
create_destination_fail_currency_notfound_test(C) ->
    Destination = make_destination(C, bank_card),
    _ = create_destination_start_mocks(C, {throwing, #fistful_CurrencyNotFound{}}),
    ?assertEqual(
        {error, {422, #{<<"message">> => <<"Currency not supported">>}}},
        create_destination_call_api(C, Destination)
    ).

-spec create_destination_fail_party_inaccessible_test(config()) -> _.
create_destination_fail_party_inaccessible_test(C) ->
    Destination = make_destination(C, bank_card),
    _ = create_destination_start_mocks(C, {throwing, #fistful_PartyInaccessible{}}),
    ?assertEqual(
        {error, {422, #{<<"message">> => <<"Identity inaccessible">>}}},
        create_destination_call_api(C, Destination)
    ).

-spec create_destination_fail_withdrawal_method_test(config()) -> _.
create_destination_fail_withdrawal_method_test(C) ->
    Destination = make_destination(C, bank_card),
    _ = create_destination_start_mocks(C, {throwing, #fistful_ForbiddenWithdrawalMethod{}}),
    ?assertEqual(
        {error, {422, #{<<"message">> => <<"Resource type not allowed">>}}},
        create_destination_call_api(C, Destination)
    ).

-spec get_destination_ok_test(config()) -> _.
get_destination_ok_test(C) ->
    Destination = make_destination(C, bank_card),
    PartyID = ?config(party, C),
    _ = wapi_ct_helper_bouncer:mock_assert_destination_op_ctx(<<"GetDestination">>, ?STRING, PartyID, C),
    _ = get_destination_start_mocks(C, {ok, Destination}),
    ?assertMatch(
        {ok, _},
        get_destination_call_api(C)
    ).

-spec get_destination_fail_notfound_test(config()) -> _.
get_destination_fail_notfound_test(C) ->
    _ = get_destination_start_mocks(C, {throwing, #fistful_DestinationNotFound{}}),
    _ = wapi_ct_helper_bouncer:mock_arbiter(wapi_ct_helper_bouncer:judge_always_forbidden(), C),
    ?assertEqual(
        {error, {404, #{}}},
        get_destination_call_api(C)
    ).

-spec bank_card_resource_test(config()) -> _.
bank_card_resource_test(C) ->
    {ok, Resource, SwagResource} = do_destination_lifecycle(bank_card, C),
    {bank_card, #'fistful_base_ResourceBankCard'{bank_card = R}} = Resource,
    ?assertEqual(<<"BankCardDestinationResource">>, maps:get(<<"type">>, SwagResource)),
    ?assertEqual(R#'fistful_base_BankCard'.token, maps:get(<<"token">>, SwagResource)),
    ?assertEqual(R#'fistful_base_BankCard'.bin, maps:get(<<"bin">>, SwagResource)),
    ?assertEqual(R#'fistful_base_BankCard'.masked_pan, maps:get(<<"lastDigits">>, SwagResource)).

-spec bitcoin_resource_test(config()) -> _.
bitcoin_resource_test(C) ->
    {ok, Resource, SwagResource} = do_destination_lifecycle(bitcoin, C),
    ?assertEqual(<<"CryptoWalletDestinationResource">>, maps:get(<<"type">>, SwagResource)),
    ?assertEqual(<<"Bitcoin">>, maps:get(<<"currency">>, SwagResource)),
    {crypto_wallet, #'fistful_base_ResourceCryptoWallet'{crypto_wallet = #'fistful_base_CryptoWallet'{id = ID}}} =
        Resource,
    ?assertEqual(ID, maps:get(<<"id">>, SwagResource)).

-spec litecoin_resource_test(config()) -> _.
litecoin_resource_test(C) ->
    {ok, Resource, SwagResource} = do_destination_lifecycle(litecoin, C),
    ?assertEqual(<<"CryptoWalletDestinationResource">>, maps:get(<<"type">>, SwagResource)),
    ?assertEqual(<<"Litecoin">>, maps:get(<<"currency">>, SwagResource)),
    {crypto_wallet, #'fistful_base_ResourceCryptoWallet'{crypto_wallet = #'fistful_base_CryptoWallet'{id = ID}}} =
        Resource,
    ?assertEqual(ID, maps:get(<<"id">>, SwagResource)).

-spec bitcoin_cash_resource_test(config()) -> _.
bitcoin_cash_resource_test(C) ->
    {ok, Resource, SwagResource} = do_destination_lifecycle(bitcoin_cash, C),
    ?assertEqual(<<"CryptoWalletDestinationResource">>, maps:get(<<"type">>, SwagResource)),
    ?assertEqual(<<"BitcoinCash">>, maps:get(<<"currency">>, SwagResource)),
    {crypto_wallet, #'fistful_base_ResourceCryptoWallet'{crypto_wallet = #'fistful_base_CryptoWallet'{id = ID}}} =
        Resource,
    ?assertEqual(ID, maps:get(<<"id">>, SwagResource)).

-spec ripple_resource_test(config()) -> _.
ripple_resource_test(C) ->
    {ok, Resource, SwagResource} = do_destination_lifecycle(ripple, C),
    ?assertEqual(<<"CryptoWalletDestinationResource">>, maps:get(<<"type">>, SwagResource)),
    ?assertEqual(<<"Ripple">>, maps:get(<<"currency">>, SwagResource)),
    {crypto_wallet, #'fistful_base_ResourceCryptoWallet'{
        crypto_wallet = #'fistful_base_CryptoWallet'{
            id = ID,
            data =
                {ripple, #'fistful_base_CryptoDataRipple'{
                    tag = Tag
                }}
        }
    }} = Resource,
    ?assertEqual(ID, maps:get(<<"id">>, SwagResource)),
    ?assertEqual(Tag, maps:get(<<"tag">>, SwagResource)).

-spec ethereum_resource_test(config()) -> _.
ethereum_resource_test(C) ->
    {ok, Resource, SwagResource} = do_destination_lifecycle(ethereum, C),
    ?assertEqual(<<"CryptoWalletDestinationResource">>, maps:get(<<"type">>, SwagResource)),
    ?assertEqual(<<"Ethereum">>, maps:get(<<"currency">>, SwagResource)),
    {crypto_wallet, #'fistful_base_ResourceCryptoWallet'{crypto_wallet = #'fistful_base_CryptoWallet'{id = ID}}} =
        Resource,
    ?assertEqual(ID, maps:get(<<"id">>, SwagResource)).

-spec usdt_resource_test(config()) -> _.
usdt_resource_test(C) ->
    {ok, Resource, SwagResource} = do_destination_lifecycle(usdt, C),
    ?assertEqual(<<"CryptoWalletDestinationResource">>, maps:get(<<"type">>, SwagResource)),
    ?assertEqual(<<"USDT">>, maps:get(<<"currency">>, SwagResource)),
    {crypto_wallet, #'fistful_base_ResourceCryptoWallet'{crypto_wallet = #'fistful_base_CryptoWallet'{id = ID}}} =
        Resource,
    ?assertEqual(ID, maps:get(<<"id">>, SwagResource)).

-spec zcash_resource_test(config()) -> _.
zcash_resource_test(C) ->
    {ok, Resource, SwagResource} = do_destination_lifecycle(zcash, C),
    ?assertEqual(<<"CryptoWalletDestinationResource">>, maps:get(<<"type">>, SwagResource)),
    ?assertEqual(<<"Zcash">>, maps:get(<<"currency">>, SwagResource)),
    {crypto_wallet, #'fistful_base_ResourceCryptoWallet'{crypto_wallet = #'fistful_base_CryptoWallet'{id = ID}}} =
        Resource,
    ?assertEqual(ID, maps:get(<<"id">>, SwagResource)).

-spec digital_wallet_resource_test(config()) -> _.
digital_wallet_resource_test(C) ->
    {ok, Resource, SwagResource} = do_destination_lifecycle(digital_wallet, C),
    ?assertEqual(<<"DigitalWalletDestinationResource">>, maps:get(<<"type">>, SwagResource)),
    ?assertEqual(<<"nomoney">>, maps:get(<<"provider">>, SwagResource)),
    {digital_wallet, #'fistful_base_ResourceDigitalWallet'{digital_wallet = #'fistful_base_DigitalWallet'{id = ID}}} =
        Resource,
    ?assertEqual(ID, maps:get(<<"id">>, SwagResource)).

-spec digital_wallet_w_token_resource_test(config()) -> _.
digital_wallet_w_token_resource_test(C) ->
    Runner = self(),
    PartyID = wapi_ct_helper:cfg(party, C),
    Token = <<"YISSTOKEN">>,
    Provider = <<"yissmoney">>,
    Resource = #{
        <<"type">> => <<"DigitalWalletDestinationResource">>,
        <<"id">> => ?STRING,
        <<"provider">> => Provider,
        <<"token">> => Token
    },
    Destination = #{
        <<"name">> => ?STRING,
        <<"identity">> => ?STRING,
        <<"currency">> => ?RUB,
        <<"resource">> => Resource
    },
    _ = wapi_ct_helper:mock_services(
        [
            {token_storage, fun('PutToken', {ID, #tds_Token{content = TokenStored}}) ->
                _ = Runner ! {token, {ID, TokenStored}},
                {ok, ok}
            end},
            {bender_thrift, fun
                ('GenerateID', _) -> {ok, ?GENERATE_ID_RESULT};
                ('GetInternalID', _) -> {ok, ?GET_INTERNAL_ID_RESULT}
            end},
            {fistful_identity, fun
                ('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)};
                ('Get', _) -> {ok, ?IDENTITY(PartyID)}
            end},
            {fistful_destination, fun('Create', _) ->
                {ok, ?DESTINATION(PartyID, ?RESOURCE_DIGITAL_WALLET)}
            end}
        ],
        C
    ),
    _ = wapi_ct_helper_bouncer:mock_assert_identity_op_ctx(<<"CreateDestination">>, ?STRING, PartyID, C),
    {ok, #{<<"resource">> := ResourceOut}} = call_api(
        fun swag_client_wallet_withdrawals_api:create_destination/3,
        #{body => Destination},
        wapi_ct_helper:cfg(context, C)
    ),
    ?assertEqual(undefined, maps:get(<<"token">>, ResourceOut, undefined)),
    receive
        {token, {ID, TokenStored}} ->
            ?assertEqual(Token, TokenStored),
            ?assertNotEqual(ID, Token)
    after 1000 ->
        error('missing token storage interaction')
    end.

%%

do_destination_lifecycle(ResourceType, C) ->
    PartyID = wapi_ct_helper:cfg(party, C),
    Identity = generate_identity(PartyID),
    Resource = generate_resource(ResourceType),
    Context = generate_context(PartyID),
    Destination = generate_destination(Identity#idnt_IdentityState.id, Resource, Context),
    _ = wapi_ct_helper:mock_services(
        [
            {bender_thrift, fun
                ('GenerateID', _) -> {ok, ?GENERATE_ID_RESULT};
                ('GetInternalID', _) -> {ok, ?GET_INTERNAL_ID_RESULT}
            end},
            {fistful_identity, fun
                ('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)};
                ('Get', _) -> {ok, ?IDENTITY(PartyID)}
            end},
            {fistful_destination, fun
                ('Create', _) -> {ok, Destination};
                ('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)};
                ('Get', _) -> {ok, Destination}
            end}
        ],
        C
    ),
    Sup0 = wapi_ct_helper:start_mocked_service_sup(?MODULE),
    _ = wapi_ct_helper_bouncer:mock_assert_identity_op_ctx(<<"CreateDestination">>, ?STRING, PartyID, Sup0),
    {ok, CreateResult} = call_api(
        fun swag_client_wallet_withdrawals_api:create_destination/3,
        #{
            body => build_destination_spec(Destination, undefined)
        },
        wapi_ct_helper:cfg(context, C)
    ),
    exit(Sup0, kill),
    _ = timer:sleep(1000),
    Sup1 = wapi_ct_helper:start_mocked_service_sup(?MODULE),
    _ = wapi_ct_helper_bouncer:mock_assert_destination_op_ctx(<<"GetDestination">>, ?STRING, PartyID, Sup1),
    {ok, GetResult} = call_api(
        fun swag_client_wallet_withdrawals_api:get_destination/3,
        #{
            binding => #{
                <<"destinationID">> => ?STRING
            }
        },
        wapi_ct_helper:cfg(context, C)
    ),
    ?assertEqual(CreateResult, GetResult),
    exit(Sup1, kill),
    _ = timer:sleep(1000),
    Sup2 = wapi_ct_helper:start_mocked_service_sup(?MODULE),
    _ = wapi_ct_helper_bouncer:mock_assert_destination_op_ctx(<<"GetDestinationByExternalID">>, ?STRING, PartyID, Sup2),
    {ok, GetByIDResult} = call_api(
        fun swag_client_wallet_withdrawals_api:get_destination_by_external_id/3,
        #{
            binding => #{
                <<"externalID">> => Destination#dst_DestinationState.external_id
            }
        },
        wapi_ct_helper:cfg(context, C)
    ),
    exit(Sup2, kill),
    _ = timer:sleep(1000),
    ?assertEqual(GetResult, GetByIDResult),
    ?assertEqual(Destination#dst_DestinationState.id, maps:get(<<"id">>, CreateResult)),
    ?assertEqual(Destination#dst_DestinationState.external_id, maps:get(<<"externalID">>, CreateResult)),
    ?assertEqual(Identity#idnt_IdentityState.id, maps:get(<<"identity">>, CreateResult)),
    ?assertEqual(
        ((Destination#dst_DestinationState.account)#account_Account.currency)#'fistful_base_CurrencyRef'.symbolic_code,
        maps:get(<<"currency">>, CreateResult)
    ),
    ?assertEqual(<<"Authorized">>, maps:get(<<"status">>, CreateResult)),
    ?assertEqual(false, maps:get(<<"isBlocked">>, CreateResult)),
    ?assertEqual(Destination#dst_DestinationState.created_at, maps:get(<<"createdAt">>, CreateResult)),
    ?assertEqual(#{<<"key">> => <<"val">>}, maps:get(<<"metadata">>, CreateResult)),
    {ok, Resource, maps:get(<<"resource">>, CreateResult)}.

-spec call_api(function(), map(), wapi_client_lib:context()) -> {ok, term()} | {error, term()}.
call_api(F, Params, Context) ->
    {Url, PreparedParams, Opts} = wapi_client_lib:make_request(Context, Params),
    Response = F(Url, PreparedParams, Opts),
    wapi_client_lib:handle_response(Response).

build_destination_spec(D, undefined) ->
    build_destination_spec(D, D#dst_DestinationState.resource);
build_destination_spec(D, Resource) ->
    #{
        <<"name">> => D#dst_DestinationState.name,
        <<"identity">> => (D#dst_DestinationState.account)#account_Account.identity,
        <<"currency">> =>
            ((D#dst_DestinationState.account)#account_Account.currency)#'fistful_base_CurrencyRef'.symbolic_code,
        <<"externalID">> => D#dst_DestinationState.external_id,
        <<"resource">> => build_resource_spec(Resource)
    }.

build_resource_spec({bank_card, R}) ->
    #{
        <<"type">> => <<"BankCardDestinationResource">>,
        <<"token">> => wapi_crypto:create_resource_token(
            {bank_card, R#'fistful_base_ResourceBankCard'.bank_card}, undefined
        )
    };
build_resource_spec({crypto_wallet, R}) ->
    Spec = build_crypto_cyrrency_spec(
        (R#'fistful_base_ResourceCryptoWallet'.crypto_wallet)#'fistful_base_CryptoWallet'.data
    ),
    Spec#{
        <<"type">> => <<"CryptoWalletDestinationResource">>,
        <<"id">> => (R#'fistful_base_ResourceCryptoWallet'.crypto_wallet)#'fistful_base_CryptoWallet'.id
    };
build_resource_spec({digital_wallet, #'fistful_base_ResourceDigitalWallet'{digital_wallet = DW}}) ->
    #{
        <<"type">> => <<"DigitalWalletDestinationResource">>,
        <<"id">> => DW#'fistful_base_DigitalWallet'.id,
        <<"provider">> => (DW#'fistful_base_DigitalWallet'.payment_service)#'fistful_base_PaymentServiceRef'.id
    };
build_resource_spec(
    {generic, #'fistful_base_ResourceGeneric'{generic = #'fistful_base_ResourceGenericData'{data = Data}}}
) ->
    #'fistful_base_Content'{data = Params} = Data,
    jsx:decode(Params);
build_resource_spec(Token) ->
    #{
        <<"type">> => <<"BankCardDestinationResource">>,
        <<"token">> => Token
    }.

build_crypto_cyrrency_spec({bitcoin, #'fistful_base_CryptoDataBitcoin'{}}) ->
    #{<<"currency">> => <<"Bitcoin">>};
build_crypto_cyrrency_spec({litecoin, #'fistful_base_CryptoDataLitecoin'{}}) ->
    #{<<"currency">> => <<"Litecoin">>};
build_crypto_cyrrency_spec({bitcoin_cash, #'fistful_base_CryptoDataBitcoinCash'{}}) ->
    #{<<"currency">> => <<"BitcoinCash">>};
build_crypto_cyrrency_spec({ripple, #'fistful_base_CryptoDataRipple'{tag = Tag}}) ->
    #{
        <<"currency">> => <<"Ripple">>,
        <<"tag">> => Tag
    };
build_crypto_cyrrency_spec({ethereum, #'fistful_base_CryptoDataEthereum'{}}) ->
    #{<<"currency">> => <<"Ethereum">>};
build_crypto_cyrrency_spec({usdt, #'fistful_base_CryptoDataUSDT'{}}) ->
    #{<<"currency">> => <<"USDT">>};
build_crypto_cyrrency_spec({zcash, #'fistful_base_CryptoDataZcash'{}}) ->
    #{<<"currency">> => <<"Zcash">>}.

uniq() ->
    genlib:bsuuid().

generate_identity(PartyID) ->
    #idnt_IdentityState{
        id = ?STRING,
        name = uniq(),
        party_id = PartyID,
        provider_id = uniq(),
        context = generate_context(PartyID)
    }.

generate_context(PartyID) ->
    #{
        ?CTX_NS =>
            {obj, #{
                {str, <<"owner">>} => {str, PartyID},
                {str, <<"name">>} => {str, uniq()},
                {str, <<"metadata">>} => {obj, #{{str, <<"key">>} => {str, <<"val">>}}}
            }}
    }.

generate_destination(IdentityID, Resource, Context) ->
    ID = ?STRING,
    #dst_DestinationState{
        id = ID,
        name = uniq(),
        status = {authorized, #dst_Authorized{}},
        account = #account_Account{
            id = ID,
            identity = IdentityID,
            currency = #'fistful_base_CurrencyRef'{
                symbolic_code = <<"RUB">>
            },
            accounter_account_id = 123
        },
        resource = Resource,
        external_id = ?STRING,
        created_at = <<"2016-03-22T06:12:27Z">>,
        blocking = unblocked,
        metadata = #{<<"key">> => {str, <<"val">>}},
        context = Context
    }.

generate_resource(generic) ->
    Data = jsx:encode(#{
        <<"type">> => ?GENERIC_RESOURCE_TYPE,
        <<"accountNumber">> => <<"1233123">>
    }),
    ID = <<"https://some.link">>,
    Type = <<"application/schema-instance+json; schema=", ID/binary>>,
    {generic, #'fistful_base_ResourceGeneric'{
        generic = #'fistful_base_ResourceGenericData'{
            data = #'fistful_base_Content'{type = Type, data = Data},
            provider = #'fistful_base_PaymentServiceRef'{id = ?GENERIC_RESOURCE_TYPE}
        }
    }};
generate_resource(bank_card) ->
    {bank_card, #'fistful_base_ResourceBankCard'{
        bank_card = #'fistful_base_BankCard'{
            token = uniq(),
            bin = <<"424242">>,
            masked_pan = <<"4242">>,
            bank_name = uniq(),
            payment_system = #'fistful_base_PaymentSystemRef'{id = <<"foo">>},
            payment_system_deprecated = visa,
            issuer_country = rus,
            card_type = debit,
            exp_date = #'fistful_base_BankCardExpDate'{
                month = 12,
                year = 2200
            }
        }
    }};
generate_resource(ResourceType) when
    ResourceType =:= bitcoin;
    ResourceType =:= litecoin;
    ResourceType =:= bitcoin_cash;
    ResourceType =:= ripple;
    ResourceType =:= ethereum;
    ResourceType =:= usdt;
    ResourceType =:= zcash
->
    {Currency, Params} = generate_crypto_wallet_data(ResourceType),
    {crypto_wallet, #'fistful_base_ResourceCryptoWallet'{
        crypto_wallet = #'fistful_base_CryptoWallet'{
            id = uniq(),
            data = {Currency, Params},
            currency = Currency
        }
    }};
generate_resource(digital_wallet) ->
    {digital_wallet, #'fistful_base_ResourceDigitalWallet'{
        digital_wallet = #'fistful_base_DigitalWallet'{
            id = uniq(),
            payment_service = #'fistful_base_PaymentServiceRef'{id = generate_digital_wallet_provider()}
        }
    }}.

generate_crypto_wallet_data(bitcoin) ->
    {bitcoin, #'fistful_base_CryptoDataBitcoin'{}};
generate_crypto_wallet_data(litecoin) ->
    {litecoin, #'fistful_base_CryptoDataLitecoin'{}};
generate_crypto_wallet_data(bitcoin_cash) ->
    {bitcoin_cash, #'fistful_base_CryptoDataBitcoinCash'{}};
generate_crypto_wallet_data(ripple) ->
    {ripple, #'fistful_base_CryptoDataRipple'{
        tag = <<"191919192">>
    }};
generate_crypto_wallet_data(ethereum) ->
    {ethereum, #'fistful_base_CryptoDataEthereum'{}};
generate_crypto_wallet_data(usdt) ->
    {usdt, #'fistful_base_CryptoDataUSDT'{}};
generate_crypto_wallet_data(zcash) ->
    {zcash, #'fistful_base_CryptoDataZcash'{}}.

generate_digital_wallet_provider() ->
    <<"nomoney">>.

make_destination(C, ResourceType) ->
    PartyID = ?config(party, C),
    Identity = generate_identity(PartyID),
    Resource = generate_resource(ResourceType),
    Context = generate_context(PartyID),
    generate_destination(Identity#idnt_IdentityState.id, Resource, Context).

create_destination_start_mocks(C, CreateDestinationResult) ->
    PartyID = ?config(party, C),

    _ = wapi_ct_helper_bouncer:mock_assert_identity_op_ctx(<<"CreateDestination">>, ?STRING, PartyID, C),
    wapi_ct_helper:mock_services(
        [
            {bender_thrift, fun('GenerateID', _) -> {ok, ?GENERATE_ID_RESULT} end},
            {fistful_identity, fun
                ('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)};
                ('Get', _) -> {ok, ?IDENTITY(PartyID)}
            end},
            {fistful_destination, fun('Create', _) -> CreateDestinationResult end}
        ],
        C
    ).

get_destination_start_mocks(C, GetDestinationResult) ->
    PartyID = ?config(party, C),
    wapi_ct_helper:mock_services(
        [
            {fistful_destination, fun
                ('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)};
                ('Get', _) -> GetDestinationResult
            end}
        ],
        C
    ).

create_destination_call_api(C, Destination) ->
    create_destination_call_api(C, Destination, undefined).

create_destination_call_api(C, Destination, Resource) ->
    call_api(
        fun swag_client_wallet_withdrawals_api:create_destination/3,
        #{
            body => build_destination_spec(Destination, Resource)
        },
        wapi_ct_helper:cfg(context, C)
    ).

get_destination_call_api(C) ->
    call_api(
        fun swag_client_wallet_withdrawals_api:get_destination/3,
        #{
            binding => #{
                <<"destinationID">> => ?STRING
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

mock_generic_schema(ResourceSchema) ->
    Raw = swag_server_wallet_schema:get(),
    Definitions = maps:get(<<"definitions">>, Raw),
    Get = fun() ->
        Raw#{
            <<"definitions">> => Definitions#{
                ?GENERIC_RESOURCE_TYPE => ResourceSchema,
                ?GENERIC_RESOURCE_NAME => #{
                    <<"type">> => <<"object">>,
                    <<"required">> => [<<"accountNumber">>],
                    <<"properties">> => #{
                        <<"accountNumber">> => #{
                            <<"type">> => <<"string">>,
                            <<"example">> => <<"0071717">>,
                            <<"pattern">> => <<"^\\d{7,8}$">>
                        }
                    }
                },
                <<"DestinationResource">> => #{
                    <<"type">> => <<"object">>,
                    <<"required">> => [<<"type">>],
                    <<"discriminator">> => <<"type">>,
                    <<"properties">> => #{
                        <<"type">> => #{
                            <<"type">> => <<"string">>,
                            <<"enum">> => [?GENERIC_RESOURCE_TYPE]
                        }
                    }
                }
            }
        }
    end,
    meck:expect(swag_server_wallet_schema, get, Get),
    meck:expect(swag_client_wallet_schema, get, Get).
