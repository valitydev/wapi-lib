-module(wapi_w2w_transfer_backend).

-type request_data() :: wapi_wallet_handler:request_data().
-type handler_context() :: wapi_handler_utils:handler_context().
-type response_data() :: wapi_handler_utils:response_data().

-type id() :: binary().
-type external_id() :: id().

-export([create/2]).
-export([get/2]).

-include_lib("fistful_proto/include/fistful_fistful_base_thrift.hrl").
-include_lib("fistful_proto/include/fistful_fistful_thrift.hrl").
-include_lib("fistful_proto/include/fistful_w2w_transfer_thrift.hrl").
-include_lib("fistful_proto/include/fistful_w2w_status_thrift.hrl").

-spec create(request_data(), handler_context()) -> {ok, response_data()} | {error, CreateError} when
    CreateError ::
        {external_id_conflict, external_id()}
        | {wallet_from | wallet_to, notfound | inaccessible}
        | bad_w2w_transfer_amount
        | not_allowed_currency
        | inconsistent_currency.
create(Params, HandlerContext) ->
    case wapi_backend_utils:gen_id(w2w_transfer, Params, HandlerContext) of
        {ok, ID} ->
            case is_id_unknown(ID, Params, HandlerContext) of
                true ->
                    Context = wapi_backend_utils:make_ctx(Params),
                    create(ID, Params, Context, HandlerContext);
                false ->
                    create(Params, HandlerContext)
            end;
        {error, {external_id_conflict, _}} = Error ->
            Error
    end.

is_id_unknown(
    ID,
    #{
        <<"sender">> := SenderID,
        <<"receiver">> := ReceiverID,
        <<"body">> := Body
    },
    HandlerContext
) ->
    case get(ID, HandlerContext) of
        {error, {identity, {w2w_transfer, {unknown_w2w_transfer, ID}}}} ->
            true;
        {ok,
            #{
                <<"id">> := ID,
                <<"sender">> := SenderID,
                <<"receiver">> := ReceiverID,
                <<"body">> := Body
            },
            _Owner} ->
            true;
        {ok, _NonMatchingIdentity, _Owner} ->
            false
    end.

create(ID, Params, Context, HandlerContext) ->
    TransferParams = marshal(transfer_params, Params#{<<"id">> => ID}),
    Request = {fistful_w2w_transfer, 'Create', {TransferParams, marshal(context, Context)}},
    case service_call(Request, HandlerContext) of
        {ok, Transfer} ->
            {ok, unmarshal(transfer, Transfer)};
        {exception, #fistful_WalletNotFound{id = ID}} ->
            {error, wallet_not_found_error(unmarshal(id, ID), Params)};
        {exception, #fistful_WalletInaccessible{id = ID}} ->
            {error, wallet_inaccessible_error(unmarshal(id, ID), Params)};
        {exception, #fistful_ForbiddenOperationCurrency{}} ->
            {error, not_allowed_currency};
        {exception, #w2w_transfer_InconsistentW2WTransferCurrency{}} ->
            {error, inconsistent_currency};
        {exception, #fistful_InvalidOperationAmount{}} ->
            {error, bad_w2w_transfer_amount}
    end.

-spec get(id(), handler_context()) -> {ok, response_data(), id()} | {error, GetError} when
    GetError :: {w2w_transfer, {unknown_w2w_transfer, id()}}.
get(ID, HandlerContext) ->
    EventRange = #'fistful_base_EventRange'{},
    Request = {fistful_w2w_transfer, 'Get', {ID, EventRange}},
    case service_call(Request, HandlerContext) of
        {ok, TransferThrift} ->
            {ok, Owner} = wapi_backend_utils:get_entity_owner(w2w_transfer, TransferThrift),
            {ok, unmarshal(transfer, TransferThrift), Owner};
        {exception, #fistful_W2WNotFound{}} ->
            {error, {w2w_transfer, {unknown_w2w_transfer, ID}}}
    end.

%%
%% Internal
%%

service_call(Params, Ctx) ->
    wapi_handler_utils:service_call(Params, Ctx).

wallet_not_found_error(WalletID, #{<<"sender">> := WalletID}) ->
    {wallet_from, notfound};
wallet_not_found_error(WalletID, #{<<"receiver">> := WalletID}) ->
    {wallet_to, notfound}.

wallet_inaccessible_error(WalletID, #{<<"sender">> := WalletID}) ->
    {wallet_from, inaccessible};
wallet_inaccessible_error(WalletID, #{<<"receiver">> := WalletID}) ->
    {wallet_to, inaccessible}.

%% Marshaling

marshal(
    transfer_params,
    #{
        <<"id">> := ID,
        <<"sender">> := SenderID,
        <<"receiver">> := ReceiverID,
        <<"body">> := Body
    } = Params
) ->
    #w2w_transfer_W2WTransferParams{
        id = marshal(id, ID),
        wallet_from_id = marshal(id, SenderID),
        wallet_to_id = marshal(id, ReceiverID),
        body = marshal(body, Body),
        external_id = maps:get(<<"externalId">>, Params, undefined)
    };
marshal(body, #{
    <<"amount">> := Amount,
    <<"currency">> := Currency
}) ->
    #'fistful_base_Cash'{
        amount = marshal(amount, Amount),
        currency = marshal(currency_ref, Currency)
    };
marshal(context, Ctx) ->
    wapi_codec:marshal(context, Ctx);
marshal(T, V) ->
    wapi_codec:marshal(T, V).

unmarshal(transfer, #w2w_transfer_W2WTransferState{
    id = ID,
    wallet_from_id = SenderID,
    wallet_to_id = ReceiverID,
    body = Body,
    created_at = CreatedAt,
    status = Status,
    external_id = ExternalID
}) ->
    genlib_map:compact(#{
        <<"id">> => unmarshal(id, ID),
        <<"createdAt">> => CreatedAt,
        <<"body">> => unmarshal(body, Body),
        <<"sender">> => unmarshal(id, SenderID),
        <<"receiver">> => unmarshal(id, ReceiverID),
        <<"status">> => unmarshal(transfer_status, Status),
        <<"externalID">> => maybe_unmarshal(id, ExternalID)
    });
unmarshal(body, #'fistful_base_Cash'{
    amount = Amount,
    currency = Currency
}) ->
    #{
        <<"amount">> => unmarshal(amount, Amount),
        <<"currency">> => unmarshal(currency_ref, Currency)
    };
unmarshal(transfer_status, {pending, _}) ->
    #{<<"status">> => <<"Pending">>};
unmarshal(transfer_status, {succeeded, _}) ->
    #{<<"status">> => <<"Succeeded">>};
unmarshal(transfer_status, {failed, #w2w_status_Failed{failure = Failure}}) ->
    #{
        <<"status">> => <<"Failed">>,
        <<"failure">> => unmarshal(failure, Failure)
    };
unmarshal(T, V) ->
    wapi_codec:unmarshal(T, V).

maybe_unmarshal(_T, undefined) ->
    undefined;
maybe_unmarshal(T, V) ->
    unmarshal(T, V).
