-module(wapi_wallet_backend).

-type handler_context() :: wapi_handler_utils:handler_context().
-type request_data() :: #{
    'partyID' := binary() | undefined,
    'limit' := pos_integer() | undefined,
    'continuationToken' := binary() | undefined,
    %% TODO Other field is obsolete, yet mentioned in API spec. Refactor
    %% request_data away after solving swag specification inconsistency.
    'currencyID' := binary() | undefined,
    _ => _
}.
-type response_data() :: wapi_handler_utils:response_data().
-type id() :: binary().

-export([list_wallets/2]).
-export([get/2]).
-export([get_account/2]).

-include_lib("damsel/include/dmsl_domain_thrift.hrl").
-include_lib("damsel/include/dmsl_payproc_thrift.hrl").

-define(LIST_RESULT(L, T), genlib_map:compact(#{<<"result">> => L, <<"continuationToken">> => T})).
-define(EMPTY_RESULT(T), ?LIST_RESULT([], T)).

-spec list_wallets(request_data(), handler_context()) -> {ok, response_data()}.
list_wallets(#{'partyID' := undefined}, _Context) ->
    {ok, ?EMPTY_RESULT(undefined)};
list_wallets(#{'partyID' := PartyID, 'limit' := Limit, 'continuationToken' := ContinuationToken}, Context) ->
    PartyRef = #domain_PartyConfigRef{id = PartyID},
    case wapi_domain_backend:get_with_related({party_config, PartyRef}, wapi_domain_backend:head(), Context) of
        {ok, _, ReferencedBy, _} ->
            F = fun
                (
                    {wallet_config, #domain_WalletConfigObject{
                        ref = #domain_WalletConfigRef{id = WalletID}, data = WalletConfig
                    }}
                ) ->
                    {true, unmarshal(wallet, {WalletID, WalletConfig})};
                (_) ->
                    false
            end,
            List = lists:filtermap(F, ReferencedBy),
            Result = paginate(List, Limit, ContinuationToken),
            {ok, Result};
        {error, not_found} ->
            {ok, ?EMPTY_RESULT(ContinuationToken)}
    end.

-spec get(id(), handler_context()) -> {ok, response_data(), id()} | {error, {wallet, notfound}}.
get(WalletID, _HandlerContext) ->
    case get_wallet_config(WalletID) of
        {ok, WalletConfig} ->
            #domain_WalletConfig{party_ref = #domain_PartyConfigRef{id = PartyID}} = WalletConfig,
            {ok, unmarshal(wallet, {WalletID, WalletConfig}), PartyID};
        {error, notfound} ->
            {error, {wallet, notfound}}
    end.

-spec get_account(id(), handler_context()) -> {ok, response_data()} | {error, {wallet, notfound}}.
get_account(WalletID, HandlerContext) ->
    DomainRevision = wapi_domain_backend:head(),
    case get_wallet_config(WalletID) of
        {ok, #domain_WalletConfig{party_ref = PartyRef, account = #domain_WalletAccount{settlement = AccountID}}} ->
            Request = {party_management, 'GetAccountState', {PartyRef, AccountID, DomainRevision}},
            case wapi_handler_utils:service_call(Request, HandlerContext) of
                {ok, AccountBalanceThrift} ->
                    {ok, unmarshal(account_state, AccountBalanceThrift)};
                {exception, #payproc_PartyNotFound{}} ->
                    {error, {wallet, notfound}};
                {exception, #payproc_AccountNotFound{}} ->
                    {error, {wallet, notfound}}
            end;
        {error, notfound} ->
            {error, {wallet, notfound}}
    end.

%% Internal

get_wallet_config(WalletID) ->
    ObjectRef = {wallet_config, #domain_WalletConfigRef{id = WalletID}},
    wapi_domain_backend:get_object(ObjectRef).

paginate([], _Limit, Token) ->
    ?EMPTY_RESULT(Token);
paginate(List0, Limit, Token) ->
    List1 = slice_with_token(List0, Token),
    case lists:sublist(List1, Limit) of
        [] ->
            ?EMPTY_RESULT(Token);
        List2 ->
            NewToken = maps:get(<<"id">>, lists:last(List2)),
            ?LIST_RESULT(List2, NewToken)
    end.

slice_with_token(List, undefined) ->
    List;
slice_with_token(List, Token) ->
    case lists:dropwhile(fun(#{<<"id">> := ID}) -> ID =/= Token end, List) of
        [] -> [];
        [_ | T] -> T
    end.

%% Marshaling

unmarshal(
    wallet,
    {WalletID, #domain_WalletConfig{
        name = Name,
        block = Blocking,
        account = #domain_WalletAccount{currency = #domain_CurrencyRef{symbolic_code = Currency}},
        party_ref = PartyRef
    }}
) ->
    genlib_map:compact(#{
        <<"id">> => unmarshal(id, WalletID),
        <<"name">> => unmarshal(string, Name),
        <<"isBlocked">> => unmarshal(blocking, Blocking),
        <<"party">> => PartyRef#domain_PartyConfigRef.id,
        <<"currency">> => Currency
    });
unmarshal(blocking, {unblocked, _}) ->
    false;
unmarshal(blocking, {blocked, _}) ->
    true;
unmarshal(account_state, #payproc_AccountState{
    own_amount = OwnAmount,
    available_amount = AvailableAmount,
    currency = #domain_Currency{symbolic_code = CurrencyCode}
}) ->
    #{
        <<"own">> => #{
            <<"amount">> => OwnAmount,
            <<"currency">> => CurrencyCode
        },
        <<"available">> => #{
            <<"amount">> => AvailableAmount,
            <<"currency">> => CurrencyCode
        }
    };
unmarshal(T, V) ->
    wapi_codec:unmarshal(T, V).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-spec paginate_test_() -> _.
paginate_test_() ->
    Items = [#{<<"id">> => integer_to_binary(I)} || I <- lists:seq(1, 10)],
    [
        ?_assertMatch(
            #{<<"result">> := L, <<"continuationToken">> := <<"10">>} when length(L) =:= 10,
            paginate(Items, 10, undefined)
        ),
        ?_assertMatch(
            #{<<"result">> := L, <<"continuationToken">> := <<"10">>} when length(L) =:= 10,
            paginate(Items, 999, undefined)
        ),
        ?_assertMatch(
            #{<<"result">> := L, <<"continuationToken">> := <<"5">>} when length(L) =:= 5,
            paginate(Items, 5, undefined)
        ),
        ?_assertMatch(
            #{<<"result">> := L, <<"continuationToken">> := <<"10">>} when length(L) =:= 5,
            paginate(Items, 5, <<"5">>)
        ),
        ?_assertMatch(
            #{<<"result">> := [], <<"continuationToken">> := <<"10">>},
            paginate(Items, 5, <<"10">>)
        ),
        ?_assertMatch(
            #{<<"result">> := [], <<"continuationToken">> := <<"999">>},
            paginate(Items, 5, <<"999">>)
        ),
        ?_assertMatch(
            #{<<"result">> := []},
            paginate([], 5, undefined)
        )
    ].

-endif.
