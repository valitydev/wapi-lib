-module(wapi_wallet_backend).

-type handler_context() :: wapi_handler_utils:handler_context().
-type response_data() :: wapi_handler_utils:response_data().
-type id() :: binary().

-export([get/2]).
-export([get_account/2]).

-include_lib("damsel/include/dmsl_domain_thrift.hrl").
-include_lib("damsel/include/dmsl_payproc_thrift.hrl").

-spec get(id(), handler_context()) -> {ok, response_data(), id()} | {error, {wallet, notfound}}.
get(WalletID, _HandlerContext) ->
    case get_wallet_config(WalletID) of
        {ok, WalletConfig} ->
            {ok, unmarshal(wallet, {WalletID, WalletConfig}), WalletConfig#domain_WalletConfig.party_id};
        {error, notfound} ->
            {error, {wallet, notfound}}
    end.

-spec get_account(id(), handler_context()) -> {ok, response_data()} | {error, {wallet, notfound}}.
get_account(WalletID, HandlerContext) ->
    case get_wallet_config(WalletID) of
        {ok, #domain_WalletConfig{party_id = PartyID, account = #domain_WalletAccount{settlement = AccountID}}} ->
            Request = {config_manager, 'GetAccountState', {PartyID, AccountID}},
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

%% Marshaling

unmarshal(
    wallet,
    {WalletID, #domain_WalletConfig{
        name = Name,
        block = Blocking,
        account = #domain_WalletAccount{currency = #domain_CurrencyRef{symbolic_code = Currency}},
        party_id = PartyID
    }}
) ->
    %% FIXME Temporary stub
    CreatedAt = ~b"1970-01-01T00:00:00Z",
    genlib_map:compact(#{
        <<"id">> => unmarshal(id, WalletID),
        <<"name">> => unmarshal(string, Name),
        <<"createdAt">> => CreatedAt,
        <<"isBlocked">> => unmarshal(blocking, Blocking),
        <<"party">> => PartyID,
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
