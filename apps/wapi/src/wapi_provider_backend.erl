-module(wapi_provider_backend).

-include_lib("fistful_proto/include/ff_proto_provider_thrift.hrl").

-type handler_context() :: wapi_handler:context().
-type response_data() :: wapi_handler:response_data().
-type id() :: binary().

-export([get_providers/2]).
-export([get_provider/2]).

-spec get_providers([binary()], handler_context()) -> [map()].
get_providers(Residences, HandlerContext) ->
    ResidenceSet = ordsets:from_list(Residences),
    Request = {fistful_provider, 'ListProviders', {}},
    {ok, Providers} = wapi_handler_utils:service_call(Request, HandlerContext),
    [
        P
     || P <- unmarshal_providers(Providers),
        ordsets:is_subset(
            ResidenceSet,
            ordsets:from_list(maps:get(<<"residences">>, P))
        )
    ].

-spec get_provider(id(), handler_context()) -> {ok, response_data()} | {error, notfound}.
get_provider(ProviderID, HandlerContext) ->
    case get_provider_thrift(ProviderID, HandlerContext) of
        {ok, Provider} ->
            {ok, unmarshal_provider(Provider)};
        {error, _} = Error ->
            Error
    end.

%% Internal

get_provider_thrift(ProviderID, HandlerContext) ->
    Request = {fistful_provider, 'GetProvider', {ProviderID}},
    case wapi_handler_utils:service_call(Request, HandlerContext) of
        {ok, _} = Result ->
            Result;
        {exception, #fistful_ProviderNotFound{}} ->
            {error, notfound}
    end.

%% Marshaling

unmarshal_providers(List) ->
    lists:map(fun(Provider) -> unmarshal_provider(Provider) end, List).

unmarshal_provider(#provider_Provider{
    id = ID,
    name = Name,
    residences = Residences
}) ->
    genlib_map:compact(#{
        <<"id">> => ID,
        <<"name">> => Name,
        <<"residences">> => Residences
    }).
