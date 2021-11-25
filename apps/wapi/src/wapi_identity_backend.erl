-module(wapi_identity_backend).

-type handler_context() :: wapi_handler:context().
-type response_data() :: wapi_handler:response_data().
-type params() :: map().
-type id() :: binary().
-type result(T, E) :: {ok, T} | {error, E}.
-type identity_state() :: ff_proto_identity_thrift:'IdentityState'().

-export_type([identity_state/0]).

-export([create_identity/2]).
-export([get_identity/2]).
-export([get_identities/2]).

-export([get_thrift_identity/2]).

-include_lib("fistful_proto/include/ff_proto_identity_thrift.hrl").
-include_lib("fistful_proto/include/ff_proto_base_thrift.hrl").

%% Pipeline

-spec get_identity(id(), handler_context()) ->
    {ok, response_data(), id()}
    | {error, {identity, notfound}}.
get_identity(IdentityID, HandlerContext) ->
    case get_thrift_identity(IdentityID, HandlerContext) of
        {ok, IdentityThrift} ->
            {ok, Owner} = wapi_backend_utils:get_entity_owner(identity, IdentityThrift),
            {ok, unmarshal(identity, IdentityThrift), Owner};
        {error, _} = Error ->
            Error
    end.

-spec create_identity(params(), handler_context()) ->
    result(
        map(),
        {provider, notfound}
        | {external_id_conflict, id()}
        | inaccessible
        | _Unexpected
    ).
create_identity(Params, HandlerContext) ->
    case create_id(identity, Params, HandlerContext) of
        {ok, ID} ->
            create_identity(ID, Params, HandlerContext);
        {error, {external_id_conflict, _}} = Error ->
            Error
    end.

create_identity(ID, Params, HandlerContext) ->
    IdentityParams = marshal(identity_params, {
        Params#{<<"id">> => ID},
        wapi_handler_utils:get_owner(HandlerContext)
    }),
    Request = {fistful_identity, 'Create', {IdentityParams, marshal(context, create_context(Params, HandlerContext))}},

    case service_call(Request, HandlerContext) of
        {ok, Identity} ->
            {ok, unmarshal(identity, Identity)};
        {exception, #fistful_PartyNotFound{}} ->
            {error, {party, notfound}};
        {exception, #fistful_ProviderNotFound{}} ->
            {error, {provider, notfound}};
        {exception, #fistful_PartyInaccessible{}} ->
            {error, inaccessible};
        {exception, Details} ->
            {error, Details}
    end.

-spec get_identities(params(), handler_context()) -> no_return().
get_identities(_Params, _Context) ->
    wapi_handler_utils:throw_not_implemented().

-spec get_thrift_identity(id(), handler_context()) ->
    {ok, identity_state()}
    | {error, {identity, notfound}}.
get_thrift_identity(IdentityID, HandlerContext) ->
    Request = {fistful_identity, 'Get', {IdentityID, #'EventRange'{}}},
    case service_call(Request, HandlerContext) of
        {ok, IdentityThrift} ->
            {ok, IdentityThrift};
        {exception, #fistful_IdentityNotFound{}} ->
            {error, {identity, notfound}}
    end.

%%
%% Internal
%%

create_id(Type, Params, HandlerContext) ->
    wapi_backend_utils:gen_id(
        Type,
        Params,
        HandlerContext
    ).

create_context(Params, HandlerContext) ->
    KV = {<<"name">>, maps:get(<<"name">>, Params, undefined)},
    wapi_backend_utils:add_to_ctx(KV, wapi_backend_utils:make_ctx(Params, HandlerContext)).

service_call(Params, Ctx) ->
    wapi_handler_utils:service_call(Params, Ctx).

%% Marshaling

marshal(
    identity_params,
    {
        Params = #{
            <<"id">> := ID,
            <<"name">> := Name,
            <<"provider">> := Provider
        },
        Owner
    }
) ->
    ExternalID = maps:get(<<"externalID">>, Params, undefined),
    #idnt_IdentityParams{
        id = marshal(id, ID),
        name = marshal(string, Name),
        party = marshal(id, Owner),
        provider = marshal(string, Provider),
        external_id = marshal(id, ExternalID)
    };
marshal(context, Ctx) ->
    wapi_codec:marshal(context, Ctx);
marshal(T, V) ->
    wapi_codec:marshal(T, V).

%%

unmarshal(identity, #idnt_IdentityState{
    id = IdentityID,
    name = Name,
    blocking = Blocking,
    provider_id = Provider,
    external_id = ExternalID,
    created_at = CreatedAt,
    context = Ctx
}) ->
    Context = unmarshal(context, Ctx),
    genlib_map:compact(#{
        <<"id">> => unmarshal(id, IdentityID),
        <<"name">> => unmarshal(string, Name),
        <<"createdAt">> => maybe_unmarshal(string, CreatedAt),
        <<"isBlocked">> => maybe_unmarshal(blocking, Blocking),
        <<"provider">> => unmarshal(id, Provider),
        <<"externalID">> => maybe_unmarshal(id, ExternalID),
        <<"metadata">> => wapi_backend_utils:get_from_ctx(<<"metadata">>, Context)
    });
unmarshal(blocking, unblocked) ->
    false;
unmarshal(blocking, blocked) ->
    true;
unmarshal(T, V) ->
    wapi_codec:unmarshal(T, V).

maybe_unmarshal(_, undefined) ->
    undefined;
maybe_unmarshal(T, V) ->
    unmarshal(T, V).
