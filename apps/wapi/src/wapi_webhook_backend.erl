-module(wapi_webhook_backend).

-export([create_webhook/2]).
-export([get_webhooks/2]).
-export([get_webhook/2]).
-export([delete_webhook/2]).

-type id() :: binary() | undefined.
-type ctx() :: wapi_handler:context().
-type req_data() :: wapi_handler:req_data().
-type handler_context() :: wapi_handler:context().
-type response_data() :: wapi_handler:response_data().

-include_lib("fistful_proto/include/ff_proto_webhooker_thrift.hrl").

-spec create_webhook(req_data(), handler_context()) -> {ok, response_data()}.
create_webhook(#{'Webhook' := Params}, HandlerContext) ->
    WebhookParams = marshal_webhook_params(Params),
    Call = {webhook_manager, 'Create', {WebhookParams}},
    Result = wapi_handler_utils:service_call(Call, HandlerContext),
    process_create_webhook_result(Result).

-spec get_webhooks(id(), ctx()) -> {ok, response_data()}.
get_webhooks(IdentityID, HandlerContext) ->
    Call = {webhook_manager, 'GetList', {IdentityID}},
    Result = wapi_handler_utils:service_call(Call, HandlerContext),
    process_get_webhooks_result(Result).

-spec get_webhook(id(), ctx()) -> {ok, response_data()} | {error, GetError} when
    GetError ::
        notfound.
get_webhook(WebhookID, HandlerContext) ->
    case encode_webhook_id(WebhookID) of
        {error, notfound} ->
            {error, {webhook, notfound}};
        EncodedID ->
            Call = {webhook_manager, 'Get', {EncodedID}},
            Result = wapi_handler_utils:service_call(Call, HandlerContext),
            process_get_webhook_result(Result)
    end.

-spec delete_webhook(id(), ctx()) -> ok | {error, DeleteError} when
    DeleteError ::
        notfound.
delete_webhook(WebhookID, HandlerContext) ->
    case encode_webhook_id(WebhookID) of
        {error, notfound} ->
            {error, {webhook, notfound}};
        EncodedID ->
            Call = {webhook_manager, 'Delete', {EncodedID}},
            Result = wapi_handler_utils:service_call(Call, HandlerContext),
            process_delete_webhook_result(Result)
    end.

process_create_webhook_result({ok, #webhooker_Webhook{} = Webhook}) ->
    {ok, unmarshal_webhook(Webhook)}.

process_get_webhooks_result({ok, Webhooks}) when is_list(Webhooks) ->
    {ok, unmarshal_webhooks(Webhooks)}.

process_get_webhook_result({ok, #webhooker_Webhook{} = Webhook}) ->
    {ok, unmarshal_webhook(Webhook)};
process_get_webhook_result({exception, #webhooker_WebhookNotFound{}}) ->
    {error, notfound}.

process_delete_webhook_result({ok, _}) ->
    ok;
process_delete_webhook_result({exception, #webhooker_WebhookNotFound{}}) ->
    {error, notfound}.

encode_webhook_id(WebhookID) ->
    try
        binary_to_integer(WebhookID)
    catch
        error:badarg ->
            {error, notfound}
    end.

%% marshaling

marshal_webhook_params(#{
    <<"identityID">> := IdentityID,
    <<"scope">> := Scope,
    <<"url">> := URL
}) ->
    WalletID = maps:get(<<"walletID">>, Scope, undefined),
    #webhooker_WebhookParams{
        identity_id = IdentityID,
        wallet_id = WalletID,
        event_filter = marshal_webhook_scope(Scope),
        url = URL
    }.

marshal_webhook_scope(#{<<"eventTypes">> := EventList}) ->
    #webhooker_EventFilter{
        types = marshal_webhook_event_types(EventList)
    }.

marshal_webhook_event_types(EventTypes) ->
    ordsets:from_list(lists:map(fun marshal_webhook_event_type/1, EventTypes)).

marshal_webhook_event_type(<<"WithdrawalStarted">>) ->
    {withdrawal, {started, #webhooker_WithdrawalStarted{}}};
marshal_webhook_event_type(<<"WithdrawalSucceeded">>) ->
    {withdrawal, {succeeded, #webhooker_WithdrawalSucceeded{}}};
marshal_webhook_event_type(<<"WithdrawalFailed">>) ->
    {withdrawal, {failed, #webhooker_WithdrawalFailed{}}};
marshal_webhook_event_type(<<"DestinationCreated">>) ->
    {destination, {created, #webhooker_DestinationCreated{}}};
marshal_webhook_event_type(<<"DestinationUnauthorized">>) ->
    {destination, {unauthorized, #webhooker_DestinationUnauthorized{}}};
marshal_webhook_event_type(<<"DestinationAuthorized">>) ->
    {destination, {authorized, #webhooker_DestinationAuthorized{}}}.

unmarshal_webhooks(Webhooks) when is_list(Webhooks) ->
    lists:map(fun(Webhook) -> unmarshal_webhook(Webhook) end, Webhooks).

unmarshal_webhook(#webhooker_Webhook{
    id = ID,
    identity_id = IdentityID,
    wallet_id = WalletID,
    event_filter = EventFilter,
    url = URL,
    pub_key = PubKey,
    enabled = Enabled
}) ->
    genlib_map:compact(#{
        <<"id">> => integer_to_binary(ID),
        <<"identityID">> => IdentityID,
        <<"active">> => wapi_codec:unmarshal(bool, Enabled),
        <<"scope">> => unmarshal_webhook_scope(EventFilter, WalletID),
        <<"url">> => URL,
        <<"publicKey">> => PubKey
    }).

unmarshal_webhook_scope(#webhooker_EventFilter{types = EventTypes}, WalletID) ->
    List = unmarshal_webhook_event_types(EventTypes),
    lists:foldl(
        fun({Topic, Type}, Acc) ->
            case maps:get(<<"topic">>, Acc, undefined) of
                undefined ->
                    genlib_map:compact(Acc#{
                        <<"topic">> => unmarshal_webhook_topic(Topic),
                        <<"walletID">> => WalletID,
                        <<"eventTypes">> => [Type]
                    });
                _ ->
                    #{<<"eventTypes">> := Types} = Acc,
                    Acc#{
                        <<"eventTypes">> := [Type | Types]
                    }
            end
        end,
        #{},
        List
    ).

unmarshal_webhook_topic(withdrawal) ->
    <<"WithdrawalsTopic">>;
unmarshal_webhook_topic(destination) ->
    <<"DestinationsTopic">>.

unmarshal_webhook_event_types(EventTypes) when is_list(EventTypes) ->
    ordsets:to_list(lists:map(fun unmarshal_webhook_event_type/1, EventTypes)).

unmarshal_webhook_event_type({withdrawal, {started, _}}) ->
    {withdrawal, <<"WithdrawalStarted">>};
unmarshal_webhook_event_type({withdrawal, {succeeded, _}}) ->
    {withdrawal, <<"WithdrawalSucceeded">>};
unmarshal_webhook_event_type({withdrawal, {failed, _}}) ->
    {withdrawal, <<"WithdrawalFailed">>};
unmarshal_webhook_event_type({destination, {created, _}}) ->
    {destination, <<"DestinationCreated">>};
unmarshal_webhook_event_type({destination, {unauthorized, _}}) ->
    {destination, <<"DestinationUnauthorized">>};
unmarshal_webhook_event_type({destination, {authorized, _}}) ->
    {destination, <<"DestinationAuthorized">>}.
