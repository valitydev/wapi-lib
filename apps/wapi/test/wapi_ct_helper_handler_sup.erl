%% @doc Top level supervisor.
%% @end

-module(wapi_ct_helper_handler_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).
-export([child_spec/0]).

%% Supervisor callbacks
-export([init/1]).

%%

-spec start_link() -> {ok, pid()} | {error, {already_started, pid()}}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%%

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    {ok, {
        {one_for_all, 0, 1},
        [wapi_ct_helper_swagger_server:child_spec([], #{wallet => {wapi_ct_helper_handler, #{}}}, #{})]
    }}.


-spec child_spec() -> [supervisor:child_spec()].
child_spec() ->
    [#{
        id    => ?MODULE,
        type  => supervisor,
        start => {wapi_ct_helper_handler_sup, start_link, []}
     }].