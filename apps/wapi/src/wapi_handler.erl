-module(wapi_handler).

%% API
-export([handle_request/5]).
-export([throw_result/1]).
-export([respond_if_forbidden/2]).

%% Behaviour definition

-type tag() :: wallet | payres.

-type operation_id() ::
    swag_client_payres:operation_id()
    | swag_server_wallet:operation_id().

-type swagger_context() ::
    swag_client_payres:request_context()
    | swag_server_wallet:request_context().

-type context() :: #{
    operation_id := operation_id(),
    woody_context := woody_context:ctx(),
    swagger_context := swagger_context()
}.

-type opts() ::
    swag_server_wallet:handler_opts(_).

-type req_data() :: #{atom() | binary() => term()}.
-type status_code() :: 200..599.
-type headers() :: cowboy:http_headers().
-type response_data() :: map() | [map()] | undefined.
-type response() :: {status_code(), headers(), response_data()}.
-type request_result() :: {ok | error, response()}.

-callback prepare(
    OperationID :: operation_id(),
    Req :: req_data(),
    Context :: context(),
    Opts :: opts()
) -> {ok, request_state()} | no_return().

-type throw(_T) :: no_return().

-type request_state() :: #{
    authorize := fun(() -> {ok, wapi_auth:resolution()} | throw(response())),
    process := fun(() -> {ok, response()} | throw(request_result()))
}.

-export_type([request_state/0]).
-export_type([response/0]).
-export_type([operation_id/0]).
-export_type([swagger_context/0]).
-export_type([context/0]).
-export_type([opts/0]).
-export_type([req_data/0]).
-export_type([status_code/0]).
-export_type([response_data/0]).
-export_type([headers/0]).
-export_type([request_result/0]).

%% API

-define(request_result, wapi_req_result).
-define(APP, wapi).

-spec handle_request(tag(), operation_id(), req_data(), swagger_context(), opts()) -> request_result().
handle_request(Tag, OperationID, Req, SwagContext, Opts) ->
    #{'X-Request-Deadline' := Header} = Req,
    case wapi_utils:parse_deadline(Header) of
        {ok, Deadline} ->
            WoodyContext = attach_deadline(Deadline, create_woody_context(Tag, Req)),
            process_request(Tag, OperationID, Req, SwagContext, Opts, WoodyContext);
        _ ->
            _ = logger:warning("Operation ~p failed due to invalid deadline header ~p", [OperationID, Header]),
            wapi_handler_utils:reply_ok(400, #{
                <<"errorType">> => <<"SchemaViolated">>,
                <<"name">> => <<"X-Request-Deadline">>,
                <<"description">> => <<"Invalid data in X-Request-Deadline header">>
            })
    end.

process_request(Tag, OperationID, Req, SwagContext0, Opts, WoodyContext) ->
    _ = logger:info("Processing request ~p", [OperationID]),
    try
        %% TODO remove this fistful specific step, when separating the wapi service.
        ok = wapi_context:save(create_wapi_context(WoodyContext)),

        SwagContext = do_authorize_api_key(SwagContext0, WoodyContext),

        Context = create_handler_context(OperationID, SwagContext, WoodyContext),
        Handler = get_handler(Tag),
        {ok, RequestState} = Handler:prepare(OperationID, Req, Context, Opts),
        #{authorize := Authorize, process := Process} = RequestState,
        {ok, Resolution} = Authorize(),
        case Resolution of
            allowed ->
                ok = logger:debug("Operation ~p authorized", [OperationID]),
                Process();
            forbidden ->
                _ = logger:info("Authorization failed"),
                wapi_handler_utils:reply_ok(401)
        end
    catch
        throw:{token_auth_failed, Reason} ->
            _ = logger:info("API Key authorization failed for ~p due to ~p", [OperationID, Reason]),
            wapi_handler_utils:reply_ok(401);
        throw:{?request_result, Result} ->
            Result;
        error:{woody_error, {Source, Class, Details}} ->
            process_woody_error(Source, Class, Details)
    after
        wapi_context:cleanup()
    end.

-spec throw_result(request_result()) -> no_return().
throw_result(Res) ->
    erlang:throw({?request_result, Res}).

-spec respond_if_forbidden(Resolution, request_result()) -> Resolution | throw(request_result()) when
    Resolution :: wapi_auth:resolution().
respond_if_forbidden(forbidden, Response) ->
    throw_result(Response);
respond_if_forbidden(allowed, _Response) ->
    allowed.

get_handler(wallet) -> wapi_wallet_handler;
get_handler(payres) -> wapi_payres_handler.

-spec create_woody_context(tag(), req_data()) -> woody_context:ctx().
create_woody_context(Tag, #{'X-Request-ID' := RequestID}) ->
    RpcID = #{trace_id := TraceID} = woody_context:new_rpc_id(genlib:to_binary(RequestID)),
    ok = scoper:add_meta(#{request_id => RequestID, trace_id => TraceID}),
    _ = logger:debug("Created TraceID for the request"),
    woody_context:new(RpcID, undefined, wapi_woody_client:get_service_deadline(Tag)).

attach_deadline(undefined, Context) ->
    Context;
attach_deadline(Deadline, Context) ->
    woody_context:set_deadline(Deadline, Context).

-spec create_handler_context(operation_id(), swagger_context(), woody_context:ctx()) -> context().
create_handler_context(OpID, SwagContext, WoodyContext) ->
    #{
        operation_id => OpID,
        woody_context => WoodyContext,
        swagger_context => SwagContext
    }.

process_woody_error(_Source, result_unexpected, _Details) ->
    wapi_handler_utils:reply_error(500);
process_woody_error(_Source, resource_unavailable, _Details) ->
    % Return an 504 since it is unknown if state of the system has been altered
    % @TODO Implement some sort of tagging for operations that mutate the state,
    % so we can still return 503s for those that don't
    wapi_handler_utils:reply_error(504);
process_woody_error(_Source, result_unknown, _Details) ->
    wapi_handler_utils:reply_error(504).

-spec create_wapi_context(woody_context:ctx()) -> wapi_context:context().
create_wapi_context(WoodyContext) ->
    ContextOptions = #{
        woody_context => WoodyContext
    },
    wapi_context:create(ContextOptions).

do_authorize_api_key(SwagContext = #{auth_context := PreAuthContext}, WoodyContext) ->
    case wapi_auth:authorize_api_key(PreAuthContext, make_token_context(SwagContext), WoodyContext) of
        {ok, AuthContext} ->
            SwagContext#{auth_context => AuthContext};
        {error, Error} ->
            throw({token_auth_failed, Error})
    end.

make_token_context(#{cowboy_req := CowboyReq}) ->
    case cowboy_req:header(<<"origin">>, CowboyReq) of
        Origin when is_binary(Origin) ->
            #{request_origin => Origin};
        undefined ->
            undefined
    end.
