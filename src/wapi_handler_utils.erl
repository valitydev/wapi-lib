-module(wapi_handler_utils).

-export([get_error_msg/1]).

-export([reply_ok/1]).
-export([reply_ok/2]).
-export([reply_ok/3]).

-export([reply_error/1]).
-export([reply_error/2]).
-export([reply_error/3]).

-export([logic_error/2]).

-export([service_call/2]).

-export([get_owner/1]).

-export([get_location/3]).
-export([maybe_with/3]).

-define(APP, wapi).

-type status_code() :: wapi_wallet_handler:status_code().
-type headers() :: wapi_wallet_handler:headers().
-type response_data() :: wapi_wallet_handler:response_data().
-type handler_context() :: wapi_wallet_handler:handler_context().
-type handler_opts() :: wapi_wallet_handler:handler_opts().
-type request_context() :: wapi_wallet_handler:request_context().
-type operation_id() :: wapi_wallet_handler:operation_id().

-type error_message() :: binary() | io_lib:chars().

-type error_type() :: external_id_conflict.
-type error_params() :: {ID :: binary(), ExternalID :: binary()}.

-type owner() :: binary() | undefined.

-export_type([owner/0]).

-export_type([handler_context/0]).
-export_type([request_context/0]).
-export_type([response_data/0]).
-export_type([operation_id/0]).

%% API

-spec get_owner(handler_context()) -> owner().
get_owner(Context) ->
    wapi_auth:get_subject_id(get_auth_context(Context)).

get_auth_context(#{swagger_context := #{auth_context := AuthContext}}) ->
    AuthContext.

-spec get_error_msg(error_message()) -> response_data().
get_error_msg(Message) ->
    #{<<"message">> => genlib:to_binary(Message)}.

-spec logic_error(error_type(), error_params()) -> {error, {status_code(), #{}, response_data()}}.
logic_error(external_id_conflict, {ID, ExternalID}) ->
    Data = #{
        <<"externalID">> => ExternalID,
        <<"id">> => ID,
        <<"message">> => <<"This 'externalID' has been used by another request">>
    },
    reply_error(409, Data).

-spec reply_ok(status_code()) -> {ok, {status_code(), #{}, undefined}}.
reply_ok(Code) ->
    reply_ok(Code, undefined).

-spec reply_ok(status_code(), response_data()) -> {ok, {status_code(), #{}, response_data()}}.
reply_ok(Code, Data) ->
    reply_ok(Code, Data, #{}).

-spec reply_ok(status_code(), response_data(), headers()) -> {ok, {status_code(), #{}, response_data()}}.
reply_ok(Code, Data, Headers) ->
    reply(ok, Code, Data, Headers).

-spec reply_error(status_code()) -> {error, {status_code(), #{}, undefined}}.
reply_error(Code) ->
    reply_error(Code, undefined).

-spec reply_error(status_code(), response_data()) -> {error, {status_code(), #{}, response_data()}}.
reply_error(Code, Data) ->
    reply_error(Code, Data, #{}).

-spec reply_error(status_code(), response_data(), headers()) -> {error, {status_code(), #{}, response_data()}}.
reply_error(Code, Data, Headers) ->
    reply(error, Code, Data, Headers).

reply(Status, Code, Data, Headers) ->
    {Status, {Code, Headers, Data}}.

-spec get_location(wapi_utils:route_match(), [binary()], handler_opts()) -> headers().
get_location(PathSpec, Params, _Opts) ->
    %% TODO pass base URL via Opts
    BaseUrl = genlib_app:env(?APP, public_endpoint),
    #{<<"Location">> => wapi_utils:get_url(BaseUrl, PathSpec, Params)}.

-spec service_call(
    {
        wapi_woody_client:service_name(),
        woody:func(),
        woody:args()
    },
    handler_context()
) -> woody:result().
service_call({ServiceName, Function, Args}, #{woody_context := WoodyContext}) ->
    wapi_woody_client:call_service(ServiceName, Function, Args, WoodyContext).

-spec maybe_with(term(), map(), fun((_Value) -> Result)) -> Result | undefined.
maybe_with(_Name, undefined, _Then) ->
    undefined;
maybe_with(Name, Params, Then) ->
    case maps:get(Name, Params, undefined) of
        V when V /= undefined ->
            Then(V);
        undefined ->
            undefined
    end.
