-module(wapi_ct_helper_swagger_server).

-export([child_spec/1]).

-export_type([logic_handler/0]).
-export_type([logic_handlers/0]).

-type logic_handler() :: swag_server_wallet:logic_handler(_).
-type logic_handlers() :: #{atom() => logic_handler()}.

-define(APP, wapi).
-define(DEFAULT_ACCEPTORS_POOLSIZE, 100).
-define(DEFAULT_IP_ADDR, "::").
-define(DEFAULT_PORT, 8080).
-define(RANCH_REF, ?MODULE).

-spec child_spec(logic_handlers()) -> supervisor:child_spec().
child_spec(LogicHandlers) ->
    {Transport, TransportOpts} = get_socket_transport(),
    CowboyOpts = get_cowboy_config(LogicHandlers),
    Protocol = cowboy_clear,
    ranch:child_spec(
        ?RANCH_REF,
        Transport,
        TransportOpts,
        Protocol,
        CowboyOpts
    ).

get_socket_transport() ->
    {ok, IP} = inet:parse_address(genlib_app:env(?APP, ip, ?DEFAULT_IP_ADDR)),
    Port = genlib_app:env(?APP, port, ?DEFAULT_PORT),
    AcceptorsPool = genlib_app:env(?APP, acceptors_poolsize, ?DEFAULT_ACCEPTORS_POOLSIZE),
    {ranch_tcp, #{socket_opts => [{ip, IP}, {port, Port}], num_acceptors => AcceptorsPool}}.

get_cowboy_config(LogicHandlers) ->
    Dispatch =
        cowboy_router:compile(
            swag_server_wallet_router:get_paths(
                maps:get(wallet, LogicHandlers),
                #{}
            )
        ),
    CowboyOpts = #{
        env => #{
            dispatch => Dispatch
        },
        middlewares => [
            cowboy_router,
            cowboy_handler
        ]
    },
    CowboyOpts.
