-module(wapi_bouncer).

-include_lib("bouncer_proto/include/bouncer_context_thrift.hrl").

-export([gather_context_fragments/4]).
-export([judge/2]).

-define(CLAIM_BOUNCER_CTX, <<"bouncer_ctx">>).

%%

-spec gather_context_fragments(
    TokenContextFragment :: token_keeper_auth_data:context_fragment(),
    UserID :: binary() | undefined,
    RequestContext :: swag_server_wallet:request_context(),
    WoodyContext :: woody_context:ctx()
) -> wapi_bouncer_context:fragments().
gather_context_fragments(TokenContextFragment, UserID, ReqCtx, WoodyCtx) ->
    {Base, External0} = wapi_bouncer_context:new(),
    External1 = External0#{<<"token-keeper">> => {encoded_fragment, TokenContextFragment}},
    {add_requester_context(ReqCtx, Base), maybe_add_userorg(UserID, External1, WoodyCtx)}.

-spec judge(wapi_bouncer_context:fragments(), woody_context:ctx()) -> wapi_auth:resolution().
judge({Acc, External}, WoodyCtx) ->
    % TODO error out early?
    {ok, RulesetID} = application:get_env(wapi, bouncer_ruleset_id),
    JudgeContext = #{fragments => External#{<<"wapi">> => Acc}},
    bouncer_client:judge(RulesetID, JudgeContext, WoodyCtx).

%%

maybe_add_userorg(undefined, External, _WoodyCtx) ->
    External;
maybe_add_userorg(UserID, External, WoodyCtx) ->
    case bouncer_context_helpers:get_user_orgs_fragment(UserID, WoodyCtx) of
        {ok, UserOrgsFragment} ->
            External#{<<"userorg">> => UserOrgsFragment};
        {error, {user, notfound}} ->
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
