-module(wapi_bouncer).

-include_lib("bouncer_proto/include/bouncer_context_thrift.hrl").

-export([gather_context_fragments/3]).
-export([judge/2]).

-define(CLAIM_BOUNCER_CTX, <<"bouncer_ctx">>).

%%

-spec gather_context_fragments(tk_auth_data:auth_data(), swag_server_wallet:request_context(), woody_context:ctx()) ->
    wapi_bouncer_context:fragments().
gather_context_fragments(AuthData, ReqCtx, WoodyCtx) ->
    {Base, External0} = wapi_bouncer_context:new(),
    External1 = External0#{<<"token-keeper">> => tk_auth_data:get_context_fragment(AuthData)},
    {add_requester_context(ReqCtx, Base), maybe_add_userorg(External1, AuthData, WoodyCtx)}.

-spec judge(wapi_bouncer_context:fragments(), woody_context:ctx()) -> wapi_auth:resolution().
judge({Acc, External}, WoodyCtx) ->
    % TODO error out early?
    {ok, RulesetID} = application:get_env(wapi, bouncer_ruleset_id),
    JudgeContext = #{fragments => External#{<<"wapi">> => Acc}},
    bouncer_client:judge(RulesetID, JudgeContext, WoodyCtx).

%%

maybe_add_userorg(External, AuthData, WoodyCtx) ->
    case tk_auth_data:get_user_id(AuthData) of
        UserID when UserID =/= undefined ->
            case bouncer_context_helpers:get_user_orgs_fragment(UserID, WoodyCtx) of
                {ok, UserOrgsFragment} ->
                    External#{<<"userorg">> => UserOrgsFragment};
                {error, {user, notfound}} ->
                    External
            end;
        undefined ->
            External
    end.

-spec add_requester_context(swag_server_wallet:request_context(), wapi_bouncer_context:acc()) ->
    wapi_bouncer_context:acc().
add_requester_context(ReqCtx, FragmentAcc) ->
    ClientPeer = maps:get(peer, ReqCtx, #{}),
    bouncer_context_helpers:add_requester(
        #{ip => maps:get(ip_address, ClientPeer, undefined)},
        FragmentAcc
    ).
