-module(wapi_token_storage).

-include_lib("tds_proto/include/tds_storage_thrift.hrl").

-export([put/2]).

-type token() :: binary().
-type id() :: binary().

-spec put(token(), woody_context:ctx()) -> id().
put(Token, WoodyContext) ->
    ID = wapi_utils:get_random_id(),
    EventHandler = wapi_redact_event_handler:new([Token], wapi_woody_event_handler),
    % NOTE
    % Collisions are possible here yet extremely unlikely.
    % Given a good source of entropy the probability is N / (2 ^ 128) where N is the number of
    % tokens stored. Moreover, token storage service does not tell us about write conficts, and
    % probably never will because it's near impossible to provide _strong_ guarantees with Riak
    % KV as a storage backend.
    {ok, _} = wapi_woody_client:call_service(
        token_storage,
        'PutToken',
        {ID, #tds_Token{content = Token}},
        WoodyContext,
        EventHandler
    ),
    ID.
