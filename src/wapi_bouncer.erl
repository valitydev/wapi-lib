-module(wapi_bouncer).

-include_lib("bouncer_proto/include/bouncer_ctx_thrift.hrl").

-export([gather_context_fragments/5]).
-export([judge/2]).

%%

-spec gather_context_fragments(
    TokenContextFragment :: token_keeper_client:context_fragment(),
    UserID :: binary() | undefined,
    PartyID :: binary() | undefined,
    IPAddress :: inet:ip_address(),
    WoodyContext :: woody_context:ctx()
) -> wapi_bouncer_context:fragments().
gather_context_fragments(TokenContextFragment, UserID, PartyID, IPAddress, WoodyCtx) ->
    {Base, External0} = wapi_bouncer_context:new(),
    External1 = External0#{<<"token-keeper">> => {encoded_fragment, TokenContextFragment}},
    External2 = maybe_add_userorg(UserID, PartyID, External1, WoodyCtx),
    {add_requester_context(IPAddress, Base), External2}.

-spec judge(wapi_bouncer_context:fragments(), woody_context:ctx()) -> wapi_auth:resolution().
judge({Acc, External}, WoodyCtx) ->
    % TODO error out early?
    {ok, RulesetID} = application:get_env(wapi_lib, bouncer_ruleset_id),
    JudgeContext = #{fragments => External#{<<"wapi">> => Acc}},
    bouncer_client:judge(RulesetID, JudgeContext, WoodyCtx).

%%

maybe_add_userorg(undefined, undefined, External, _WoodyCtx) ->
    External;
maybe_add_userorg(undefined, PartyID, External, WoodyCtx) ->
    case bouncer_context_helpers:get_party_org_fragment(PartyID, WoodyCtx) of
        {ok, PartyOrgFragment} ->
            External#{<<"partyorg">> => PartyOrgFragment};
        {error, {party, notfound}} ->
            External
    end;
maybe_add_userorg(UserID, _PartyID, External, WoodyCtx) ->
    case bouncer_context_helpers:get_user_orgs_fragment(UserID, WoodyCtx) of
        {ok, UserOrgsFragment} ->
            External#{<<"userorg">> => UserOrgsFragment};
        {error, {user, notfound}} ->
            External
    end.

-spec add_requester_context(inet:ip_address(), wapi_bouncer_context:acc()) -> wapi_bouncer_context:acc().
add_requester_context(IPAddress, FragmentAcc) ->
    bouncer_context_helpers:add_requester(
        #{ip => IPAddress},
        FragmentAcc
    ).
