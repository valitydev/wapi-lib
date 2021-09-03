-ifndef(wapi_bouncer_data_included__).
-define(wapi_bouncer_data_included__, ok).

-include_lib("bouncer_proto/include/bouncer_decisions_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_context_v1_thrift.hrl").

-define(JUDGEMENT(Resolution), #bdcs_Judgement{resolution = Resolution}).
-define(ALLOWED, {allowed, #bdcs_ResolutionAllowed{}}).
-define(FORBIDDEN, {forbidden, #bdcs_ResolutionForbidden{}}).

-define(CTX_ENTITY(ID), #bctx_v1_Entity{id = ID}).

-define(CTX_WAPI(Op), #bctx_v1_ContextWalletAPI{op = Op}).

-define(CTX_WAPI_OP(ID), #bctx_v1_WalletAPIOperation{id = ID}).

-define(CTX_PARTY_OP(ID, PartyID), #bctx_v1_WalletAPIOperation{
    id = ID,
    party = PartyID
}).

-define(CTX_IDENTITY_OP(ID, IdentityID), #bctx_v1_WalletAPIOperation{
    id = ID,
    identity = IdentityID
}).

-define(CTX_DESTINAION_OP(ID, DestinaionID), #bctx_v1_WalletAPIOperation{
    id = ID,
    destination = DestinaionID
}).

-define(CTX_WALLET_OP(ID, WalletID), #bctx_v1_WalletAPIOperation{
    id = ID,
    wallet = WalletID
}).

-define(CTX_WITHDRAWAL_OP(ID, WithdrawalID), #bctx_v1_WalletAPIOperation{
    id = ID,
    withdrawal = WithdrawalID
}).

-define(CTX_W2W_TRANSFER_OP(ID, W2WTransferID), #bctx_v1_WalletAPIOperation{
    id = ID,
    w2w_transfer = W2WTransferID
}).

-define(assertContextMatches(Expect), fun(Context) ->
    try
        ?assertMatch(Expect, Context),
        {ok, ?JUDGEMENT(?ALLOWED)}
    catch
        error:AssertMatchError:Stacktrace ->
            logger:error("failed ~p at ~p", [AssertMatchError, Stacktrace]),
            logger:error("~n Expect ~p ~n Context ~p", [Expect, Context]),
            {throwing, #bdcs_InvalidContext{}}
    end
end).

-endif.
