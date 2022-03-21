-module(wapi_destination_backend).

-type req_data() :: wapi_handler:req_data().
-type handler_context() :: wapi_handler:context().
-type response_data() :: wapi_handler:response_data().
-type id() :: binary().
-type external_id() :: binary().

-export([create/2]).
-export([get/2]).
-export([get_by_external_id/2]).

-include_lib("fistful_proto/include/ff_proto_destination_thrift.hrl").

%% Pipeline

-import(wapi_pipeline, [do/1, unwrap/1]).

-spec create(req_data(), handler_context()) -> {ok, response_data()} | {error, DestinationError} when
    DestinationError ::
        {invalid_resource_token, binary()}
        | {invalid_generic_resource, {binary(), unknown_resource}}
        | {identity, notfound}
        | {currency, notfound}
        | inaccessible
        | {external_id_conflict, {id(), external_id()}}.
create(Params, HandlerContext) ->
    do(fun() ->
        ResourceThrift = unwrap(construct_resource(maps:get(<<"resource">>, Params))),
        ID = unwrap(generate_id(Params, ResourceThrift, HandlerContext)),
        unwrap(create_request(ID, Params, ResourceThrift, HandlerContext))
    end).

generate_id(Params, ResourceThrift, HandlerContext) ->
    Resource = maps:get(<<"resource">>, Params),
    % replacing token with an tokenizedResource is need for naive idempotent algo.
    NewParams = Params#{
        <<"resource">> => Resource#{
            <<"token">> => undefined,
            <<"tokenizedResource">> => tokenize_resource(ResourceThrift)
        }
    },
    case wapi_backend_utils:gen_id(destination, NewParams, HandlerContext) of
        {ok, ID} ->
            {ok, ID};
        {error, {external_id_conflict, ID}} ->
            % Delete after deploy
            ExternalID = maps:get(<<"externalID">>, Params, undefined),
            logger:warning("external_id_conflict: ~p. try old hashing", [{ID, ExternalID}]),
            generate_id_legacy(Params, HandlerContext)
    end.

generate_id_legacy(Params, HandlerContext) ->
    case wapi_backend_utils:gen_id(destination, Params, HandlerContext) of
        {ok, ID} ->
            {ok, ID};
        {error, {external_id_conflict, ID}} ->
            ExternalID = maps:get(<<"externalID">>, Params, undefined),
            {error, {external_id_conflict, {ID, ExternalID}}}
    end.

create_request(ID, Params, ResourceThrift, HandlerContext) ->
    % mixing the attributes needed for marshaling
    MarshaledParams = marshal(destination_params, Params#{
        <<"id">> => ID,
        <<"resourceThrift">> => ResourceThrift
    }),
    MarshaledContext = marshal(context, wapi_backend_utils:make_ctx(Params, HandlerContext)),
    Request = {fistful_destination, 'Create', {MarshaledParams, MarshaledContext}},
    case service_call(Request, HandlerContext) of
        {ok, Destination} ->
            {ok, unmarshal(destination, Destination)};
        {exception, #fistful_IdentityNotFound{}} ->
            {error, {identity, notfound}};
        {exception, #fistful_CurrencyNotFound{}} ->
            {error, {currency, notfound}};
        {exception, #fistful_PartyInaccessible{}} ->
            {error, inaccessible};
        {exception, Details} ->
            {error, Details}
    end.

-spec get(id(), handler_context()) ->
    {ok, response_data(), id()}
    | {error, {destination, notfound}}.
get(DestinationID, HandlerContext) ->
    Request = {fistful_destination, 'Get', {DestinationID, #'EventRange'{}}},
    case service_call(Request, HandlerContext) of
        {ok, DestinationThrift} ->
            {ok, Owner} = wapi_backend_utils:get_entity_owner(destination, DestinationThrift),
            {ok, unmarshal(destination, DestinationThrift), Owner};
        {exception, #fistful_DestinationNotFound{}} ->
            {error, {destination, notfound}}
    end.

-spec get_by_external_id(external_id(), handler_context()) ->
    {ok, response_data(), id()}
    | {error, {destination, notfound}}
    | {error, {external_id, {unknown_external_id, external_id()}}}.
get_by_external_id(ExternalID, HandlerContext = #{woody_context := WoodyContext}) ->
    PartyID = wapi_handler_utils:get_owner(HandlerContext),
    IdempotentKey = wapi_backend_utils:get_idempotent_key(destination, PartyID, ExternalID),
    case bender_client:get_internal_id(IdempotentKey, WoodyContext) of
        {ok, {DestinationID, _}, _CtxData} ->
            get(DestinationID, HandlerContext);
        {error, internal_id_not_found} ->
            {error, {external_id, {unknown_external_id, ExternalID}}}
    end.

%%
%% Internal
%%

construct_resource(#{
    <<"token">> := Token,
    <<"type">> := Type
}) ->
    case wapi_backend_utils:decode_resource(Token) of
        {ok, Resource} ->
            {bank_card, BankCard} = Resource,
            {ok, {bank_card, #'ResourceBankCard'{bank_card = BankCard}}};
        {error, Error} ->
            logger:warning("~p token decryption failed: ~p", [Type, Error]),
            {error, {invalid_resource_token, Type}}
    end;
construct_resource(
    #{
        <<"type">> := <<"CryptoWalletDestinationResource">>,
        <<"id">> := CryptoWalletID
    } = Resource
) ->
    CostructedResource =
        {crypto_wallet, #{
            crypto_wallet => #{
                id => CryptoWalletID,
                data => marshal_crypto_currency_data(Resource)
            }
        }},
    {ok, wapi_codec:marshal(resource, CostructedResource)};
construct_resource(
    #{
        <<"type">> := <<"DigitalWalletDestinationResource">>,
        <<"id">> := DigitalWalletID,
        <<"provider">> := Provider
    }
) ->
    ConstructedResource =
        {digital_wallet, #{
            digital_wallet => #{
                id => marshal(string, DigitalWalletID),
                payment_service => #{id => marshal(string, Provider)}
            }
        }},
    {ok, wapi_codec:marshal(resource, ConstructedResource)};
construct_resource(
    Resource = #{
        <<"type">> := GenericResourceType
    }
) ->
    case prepare_generic_resource_data(GenericResourceType, Resource) of
        {ok, Data} ->
            ConstructedResource =
                {generic, #{
                    generic => #{
                        payment_service => #{id => marshal(string, GenericResourceType)},
                        data => Data
                    }
                }},
            {ok, wapi_codec:marshal(resource, ConstructedResource)};
        {error, Error} ->
            {error, {invalid_generic_resource, {GenericResourceType, Error}}}
    end.

tokenize_resource({bank_card, #'ResourceBankCard'{bank_card = BankCard}}) ->
    wapi_backend_utils:tokenize_resource({bank_card, BankCard});
tokenize_resource(Value) ->
    wapi_backend_utils:tokenize_resource(Value).

prepare_generic_resource_data(ResourceType, Resource) ->
    Schema = swag_server_wallet_schema:get(),
    Definitions = maps:get(<<"definitions">>, Schema),
    ResourceSchema = maps:get(ResourceType, Definitions),
    case maps:get(<<"x-vality-genericMethod">>, ResourceSchema, undefined) of
        GenericMethodSchema when GenericMethodSchema =/= undefined ->
            SchemaID =
                case maps:get(<<"schema">>, GenericMethodSchema, #{}) of
                    #{<<"id">> := ID} ->
                        <<"application/schema-instance+json; schema=", ID/binary>>;
                    _Empty ->
                        <<"application/json">>
                end,
            {ok, #{type => SchemaID, data => jsx:encode(Resource)}};
        undefined ->
            {error, unknown_resource}
    end.

service_call(Params, Context) ->
    wapi_handler_utils:service_call(Params, Context).

%% Marshaling

marshal(
    destination_params,
    Params = #{
        <<"id">> := ID,
        <<"identity">> := IdentityID,
        <<"currency">> := CurrencyID,
        <<"name">> := Name,
        <<"resourceThrift">> := Resource
    }
) ->
    ExternalID = maps:get(<<"externalID">>, Params, undefined),
    #dst_DestinationParams{
        id = marshal(id, ID),
        identity = marshal(id, IdentityID),
        name = marshal(string, Name),
        currency = marshal(string, CurrencyID),
        external_id = maybe_marshal(id, ExternalID),
        resource = Resource
    };
marshal(context, Context) ->
    wapi_codec:marshal(context, Context);
marshal(T, V) ->
    wapi_codec:marshal(T, V).

maybe_marshal(_, undefined) ->
    undefined;
maybe_marshal(T, V) ->
    marshal(T, V).

unmarshal(destination, #dst_DestinationState{
    id = DestinationID,
    name = Name,
    account = Account,
    external_id = ExternalID,
    created_at = CreatedAt,
    resource = Resource,
    status = Status,
    blocking = Blocking,
    context = Context
}) ->
    #{
        identity := Identity,
        currency := Currency
    } = unmarshal(account, Account),
    UnmarshaledContext = unmarshal(context, Context),
    genlib_map:compact(#{
        <<"id">> => unmarshal(id, DestinationID),
        <<"name">> => unmarshal(string, Name),
        <<"status">> => unmarshal(status, Status),
        <<"isBlocked">> => maybe_unmarshal(blocking, Blocking),
        <<"identity">> => Identity,
        <<"currency">> => Currency,
        <<"createdAt">> => CreatedAt,
        <<"resource">> => unmarshal(resource, Resource),
        <<"externalID">> => maybe_unmarshal(id, ExternalID),
        <<"metadata">> => wapi_backend_utils:get_from_ctx(<<"metadata">>, UnmarshaledContext)
    });
unmarshal(blocking, unblocked) ->
    false;
unmarshal(blocking, blocked) ->
    true;
unmarshal(status, {authorized, #dst_Authorized{}}) ->
    <<"Authorized">>;
unmarshal(status, {unauthorized, #dst_Unauthorized{}}) ->
    <<"Unauthorized">>;
unmarshal(
    resource,
    {bank_card, #'ResourceBankCard'{
        bank_card = #'BankCard'{
            token = Token,
            bin = Bin,
            masked_pan = MaskedPan
        }
    }}
) ->
    genlib_map:compact(#{
        <<"type">> => <<"BankCardDestinationResource">>,
        <<"token">> => unmarshal(string, Token),
        <<"bin">> => unmarshal(string, Bin),
        <<"lastDigits">> => wapi_utils:get_last_pan_digits(MaskedPan)
    });
unmarshal(
    resource,
    {crypto_wallet, #'ResourceCryptoWallet'{
        crypto_wallet = #'CryptoWallet'{
            id = CryptoWalletID,
            data = Data
        }
    }}
) ->
    {Currency, Params} = unmarshal_crypto_currency_data(Data),
    genlib_map:compact(#{
        <<"type">> => <<"CryptoWalletDestinationResource">>,
        <<"id">> => unmarshal(string, CryptoWalletID),
        <<"currency">> => Currency,
        <<"tag">> => genlib_map:get(tag, Params)
    });
unmarshal(
    resource,
    {digital_wallet, #'ResourceDigitalWallet'{
        digital_wallet = #'DigitalWallet'{
            id = DigitalWalletID,
            payment_service = #'PaymentServiceRef'{id = Provider}
        }
    }}
) ->
    #{
        <<"type">> => <<"DigitalWalletDestinationResource">>,
        <<"id">> => unmarshal(string, DigitalWalletID),
        <<"provider">> => unmarshal(string, Provider)
    };
unmarshal(
    resource,
    {generic, #'ResourceGeneric'{
        generic = #'ResourceGenericData'{
            provider = #'PaymentServiceRef'{id = Provider},
            data = #'Content'{data = Data}
        }
    }}
) ->
    Resource = jsx:decode(Data),
    Resource#{<<"type">> => Provider};
unmarshal(context, Context) ->
    wapi_codec:unmarshal(context, Context);
unmarshal(T, V) ->
    wapi_codec:unmarshal(T, V).

maybe_unmarshal(_, undefined) ->
    undefined;
maybe_unmarshal(T, V) ->
    unmarshal(T, V).

marshal_crypto_currency_data(Resource) ->
    #{
        <<"currency">> := CryptoCurrencyName
    } = Resource,
    Name = marshal_crypto_currency_name(CryptoCurrencyName),
    Params = marshal_crypto_currency_params(Name, Resource),
    {Name, Params}.

unmarshal_crypto_currency_data({Name, Params}) ->
    {unmarshal_crypto_currency_name(Name), unmarshal_crypto_currency_params(Name, Params)}.

marshal_crypto_currency_name(<<"Bitcoin">>) -> bitcoin;
marshal_crypto_currency_name(<<"Litecoin">>) -> litecoin;
marshal_crypto_currency_name(<<"BitcoinCash">>) -> bitcoin_cash;
marshal_crypto_currency_name(<<"Ripple">>) -> ripple;
marshal_crypto_currency_name(<<"Ethereum">>) -> ethereum;
marshal_crypto_currency_name(<<"USDT">>) -> usdt;
marshal_crypto_currency_name(<<"Zcash">>) -> zcash.

unmarshal_crypto_currency_name(bitcoin) -> <<"Bitcoin">>;
unmarshal_crypto_currency_name(litecoin) -> <<"Litecoin">>;
unmarshal_crypto_currency_name(bitcoin_cash) -> <<"BitcoinCash">>;
unmarshal_crypto_currency_name(ripple) -> <<"Ripple">>;
unmarshal_crypto_currency_name(ethereum) -> <<"Ethereum">>;
unmarshal_crypto_currency_name(usdt) -> <<"USDT">>;
unmarshal_crypto_currency_name(zcash) -> <<"Zcash">>.

marshal_crypto_currency_params(ripple, Resource) ->
    Tag = maps:get(<<"tag">>, Resource, undefined),
    #{
        tag => maybe_marshal(string, Tag)
    };
marshal_crypto_currency_params(_Other, _Resource) ->
    #{}.

unmarshal_crypto_currency_params(ripple, #'CryptoDataRipple'{tag = Tag}) ->
    genlib_map:compact(#{
        tag => maybe_unmarshal(string, Tag)
    });
unmarshal_crypto_currency_params(_Other, _Params) ->
    #{}.
