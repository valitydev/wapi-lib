-ifndef(wapi_bouncer_data_included__).
-define(wapi_bouncer_data_included__, ok).

-include_lib("bouncer_proto/include/bouncer_base_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_decision_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_ctx_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_ctx_v1_thrift.hrl").

-include_lib("stdlib/include/assert.hrl").

-define(JUDGEMENT(Resolution), #decision_Judgement{resolution = Resolution}).
-define(ALLOWED, {allowed, #decision_ResolutionAllowed{}}).
-define(FORBIDDEN, {forbidden, #decision_ResolutionForbidden{}}).

-define(CTX_ENTITY(ID), #ctx_v1_Entity{id = ID}).

-define(CTX_WAPI(Op), #ctx_v1_ContextWalletAPI{op = Op}).

-define(CTX_WAPI_OP(ID), #ctx_v1_WalletAPIOperation{id = ID}).

-define(CTX_PARTY_OP(ID, PartyID), #ctx_v1_WalletAPIOperation{
    id = ID,
    party = PartyID
}).

-define(CTX_IDENTITY_OP(ID, PartyID), #ctx_v1_WalletAPIOperation{
    id = ID,
    party = PartyID
}).

-define(CTX_DESTINAION_OP(ID, DestinaionID), #ctx_v1_WalletAPIOperation{
    id = ID,
    destination = DestinaionID
}).

-define(CTX_WALLET_OP(ID, WalletID), #ctx_v1_WalletAPIOperation{
    id = ID,
    wallet = WalletID
}).

-define(CTX_WITHDRAWAL_OP(ID, WithdrawalID), #ctx_v1_WalletAPIOperation{
    id = ID,
    withdrawal = WithdrawalID
}).

-define(CTX_W2W_TRANSFER_OP(ID, W2WTransferID), #ctx_v1_WalletAPIOperation{
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
            {throwing, #decision_InvalidContext{}}
    end
end).

-endif.
