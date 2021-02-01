-module(wapi_context).

-export([create/0]).
-export([create/1]).
-export([save/1]).
-export([load/0]).
-export([cleanup/0]).

-export([get_woody_context/1]).
-export([set_woody_context/2]).

-opaque context() :: #{
    woody_context := woody_context()
}.

-type options() :: #{
    woody_context => woody_context()
}.

-export_type([context/0]).
-export_type([options/0]).

%% Internal types

-type woody_context() :: woody_context:ctx().

-define(REGISTRY_KEY, {p, l, {?MODULE, stored_context}}).

%% API

-spec create() -> context().
create() ->
    create(#{}).

-spec create(options()) -> context().
create(Options0) ->
    ensure_woody_context_exists(Options0).

-spec save(context()) -> ok.
save(Context) ->
    true =
        try
            gproc:reg(?REGISTRY_KEY, Context)
        catch
            error:badarg ->
                gproc:set_value(?REGISTRY_KEY, Context)
        end,
    ok.

-spec load() -> context() | no_return().
load() ->
    gproc:get_value(?REGISTRY_KEY).

-spec cleanup() -> ok.
cleanup() ->
    true = gproc:unreg(?REGISTRY_KEY),
    ok.

-spec get_woody_context(context()) -> woody_context().
get_woody_context(#{woody_context := WoodyContext}) ->
    WoodyContext.

-spec set_woody_context(woody_context(), context()) -> context().
set_woody_context(WoodyContext, Context) ->
    Context#{woody_context => WoodyContext}.

%% Internal functions

-spec ensure_woody_context_exists(options()) -> options().
ensure_woody_context_exists(#{woody_context := _WoodyContext} = Options) ->
    Options;
ensure_woody_context_exists(Options) ->
    Options#{woody_context => woody_context:new()}.
