-module(wapi_wallet_backend).

-type handler_context() :: wapi_handler_utils:handler_context().
-type response_data() :: wapi_handler_utils:response_data().
-type id() :: binary().

-export([get_account/2]).

-include_lib("damsel/include/dmsl_payproc_thrift.hrl").
-include_lib("damsel/include/dmsl_domain_thrift.hrl").

-spec get_account(id(), handler_context()) -> {ok, response_data()} | {error, {wallet, notfound}}.
get_account(WalletID, HandlerContext) ->
    case wapi_domain_backend:get_wallet_config(WalletID) of
        {ok, {
            #{
                <<"partyID">> := PartyID,
                <<"account">> := #{
                    <<"currency">> := _Currency,
                    <<"settlement">> := AccountID
                }
            },
            _
        }} ->
            Request = {config_manager, 'GetAccountState', {PartyID, AccountID}},
            case wapi_handler_utils:service_call(Request, HandlerContext) of
                {ok, AccountBalanceThrift} ->
                    {ok, unmarshal_wallet_account_balance(AccountBalanceThrift)};
                {exception, #payproc_PartyNotFound{}} ->
                    {error, {wallet, notfound}};
                {exception, #payproc_AccountNotFound{}} ->
                    {error, {wallet, notfound}}
            end;
        {error, notfound} ->
            {error, {wallet, notfound}}
    end.

%% Marshaling

unmarshal_wallet_account_balance(#payproc_AccountState{
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
    }.
