-module(wapi_stat_backend).

-include_lib("fistful_proto/include/fistful_fistful_base_thrift.hrl").
-include_lib("fistful_proto/include/fistful_stat_thrift.hrl").

-export([list_wallets/2]).
-export([list_withdrawals/2]).
-export([list_deposits/2]).
-export([list_destinations/2]).
-export([list_identities/2]).
-export([list_deposit_reverts/2]).
-export([list_deposit_adjustments/2]).

-type request_data() :: wapi_wallet_handler:request_data().
-type handler_context() :: wapi_handler_utils:handler_context().
-type response_data() :: wapi_handler_utils:response_data().

-spec list_wallets(request_data(), handler_context()) -> {ok, response_data()} | {error, StatError} when
    StatError :: {invalid | bad_token, binary()}.
list_wallets(Params, Context) ->
    service_call(wallets, Params, Context).

-spec list_withdrawals(request_data(), handler_context()) -> {ok, response_data()} | {error, StatError} when
    StatError :: {invalid | bad_token, binary()}.
list_withdrawals(Params, Context) ->
    service_call(withdrawals, Params, Context).

-spec list_deposits(request_data(), handler_context()) -> {ok, response_data()} | {error, StatError} when
    StatError :: {invalid | bad_token, binary()}.
list_deposits(Params, Context) ->
    service_call(deposits, Params, Context).

-spec list_destinations(request_data(), handler_context()) -> {ok, response_data()} | {error, StatError} when
    StatError :: {invalid | bad_token, binary()}.
list_destinations(Params, Context) ->
    service_call(destinations, Params, Context).

-spec list_identities(request_data(), handler_context()) -> {ok, response_data()} | {error, StatError} when
    StatError :: {invalid | bad_token, binary()}.
list_identities(Params, Context) ->
    service_call(identities, Params, Context).

-spec list_deposit_reverts(request_data(), handler_context()) -> {ok, response_data()} | {error, StatError} when
    StatError :: {invalid | bad_token, binary()}.
list_deposit_reverts(Params, Context) ->
    service_call(deposit_reverts, Params, Context).

-spec list_deposit_adjustments(request_data(), handler_context()) -> {ok, response_data()} | {error, StatError} when
    StatError :: {invalid | bad_token, binary()}.
list_deposit_adjustments(Params, Context) ->
    service_call(deposit_adjustments, Params, Context).

service_call(StatTag, Params, Context) ->
    Req = create_request(
        create_dsl(StatTag, Params),
        maps:get('continuationToken', Params, undefined)
    ),
    process_result(
        wapi_handler_utils:service_call({fistful_stat, method(StatTag), {Req}}, Context)
    ).

method(wallets) -> 'GetWallets';
method(withdrawals) -> 'GetWithdrawals';
method(deposits) -> 'GetDeposits';
method(destinations) -> 'GetDestinations';
method(identities) -> 'GetIdentities';
method(deposit_reverts) -> 'GetDepositReverts';
method(deposit_adjustments) -> 'GetDepositAdjustments'.

create_dsl(StatTag, Req) ->
    Query = create_query(StatTag, Req),
    QueryParams = #{<<"size">> => genlib_map:get(limit, Req)},
    jsx:encode(#{
        <<"query">> => merge_and_compact(
            maps:put(genlib:to_binary(StatTag), genlib_map:compact(Query), #{}),
            QueryParams
        )
    }).

create_query(withdrawals, Req) ->
    #{
        <<"party_id">> => maps:get('partyID', Req),
        <<"wallet_id">> => genlib_map:get('walletID', Req),
        <<"identity_id">> => genlib_map:get('identityID', Req),
        <<"withdrawal_id">> => genlib_map:get('withdrawalID', Req),
        <<"destination_id">> => genlib_map:get('destinationID', Req),
        <<"external_id">> => genlib_map:get('externalID', Req),
        <<"status">> => genlib_map:get(status, Req),
        <<"from_time">> => get_time('createdAtFrom', Req),
        <<"to_time">> => get_time('createdAtTo', Req),
        <<"amount_from">> => genlib_map:get('amountFrom', Req),
        <<"amount_to">> => genlib_map:get('amountTo', Req),
        <<"currency_code">> => genlib_map:get('currencyID', Req)
    };
create_query(deposits, Req) ->
    #{
        <<"party_id">> => maps:get('partyID', Req),
        <<"wallet_id">> => genlib_map:get('walletID', Req),
        <<"identity_id">> => genlib_map:get('identityID', Req),
        <<"deposit_id">> => genlib_map:get('depositID', Req),
        <<"source_id">> => genlib_map:get('sourceID', Req),
        <<"status">> => genlib_map:get(status, Req),
        <<"from_time">> => get_time('createdAtFrom', Req),
        <<"to_time">> => get_time('createdAtTo', Req),
        <<"amount_from">> => genlib_map:get('amountFrom', Req),
        <<"amount_to">> => genlib_map:get('amountTo', Req),
        <<"currency_code">> => genlib_map:get('currencyID', Req),
        <<"revert_status">> => genlib_map:get('revertStatus', Req)
    };
create_query(wallets, Req) ->
    #{
        <<"party_id">> => maps:get('partyID', Req),
        <<"identity_id">> => genlib_map:get('identityID', Req),
        <<"currency_code">> => genlib_map:get('currencyID', Req)
    };
create_query(destinations, Req) ->
    #{
        <<"party_id">> => maps:get('partyID', Req),
        <<"identity_id">> => genlib_map:get('identityID', Req),
        <<"currency_code">> => genlib_map:get('currencyID', Req)
    };
create_query(identities, Req) ->
    #{
        <<"party_id">> => maps:get('partyID', Req),
        <<"provider_id">> => genlib_map:get('providerID', Req),
        <<"class">> => genlib_map:get(class, Req),
        <<"level">> => genlib_map:get(level, Req)
    };
create_query(deposit_reverts, Req) ->
    #{
        <<"party_id">> => maps:get('partyID', Req),
        <<"identity_id">> => genlib_map:get('identityID', Req),
        <<"source_id">> => genlib_map:get('sourceID', Req),
        <<"wallet_id">> => genlib_map:get('walletID', Req),
        <<"deposit_id">> => genlib_map:get('depositID', Req),
        <<"revert_id">> => genlib_map:get('revertID', Req),
        <<"amount_from">> => genlib_map:get('amountFrom', Req),
        <<"amount_to">> => genlib_map:get('amountTo', Req),
        <<"currency_code">> => genlib_map:get('currencyID', Req),
        <<"status">> => genlib_map:get(status, Req),
        <<"deposit_status">> => genlib_map:get('depositStatus', Req),
        <<"from_time">> => get_time('createdAtFrom', Req),
        <<"to_time">> => get_time('createdAtTo', Req)
    };
create_query(deposit_adjustments, Req) ->
    #{
        <<"party_id">> => maps:get('partyID', Req),
        <<"identity_id">> => genlib_map:get('identityID', Req),
        <<"source_id">> => genlib_map:get('sourceID', Req),
        <<"wallet_id">> => genlib_map:get('walletID', Req),
        <<"deposit_id">> => genlib_map:get('depositID', Req),
        <<"adjustment_id">> => genlib_map:get('adjustmentID', Req),
        <<"amount_from">> => genlib_map:get('amountFrom', Req),
        <<"amount_to">> => genlib_map:get('amountTo', Req),
        <<"currency_code">> => genlib_map:get('currencyID', Req),
        <<"status">> => genlib_map:get(status, Req),
        <<"deposit_status">> => genlib_map:get('depositStatus', Req),
        <<"from_time">> => get_time('createdAtFrom', Req),
        <<"to_time">> => get_time('createdAtTo', Req)
    }.

create_request(Dsl, Token) ->
    #stat_StatRequest{
        dsl = Dsl,
        continuation_token = Token
    }.

process_result(
    {ok, #stat_StatResponse{
        data = {QueryType, Data},
        continuation_token = ContinuationToken
    }}
) ->
    DecodedData = [unmarshal_response(QueryType, S) || S <- Data],
    Response = genlib_map:compact(#{
        <<"result">> => DecodedData,
        <<"continuationToken">> => ContinuationToken
    }),
    {ok, Response};
process_result({exception, #stat_InvalidRequest{errors = Errors}}) ->
    FormattedErrors = format_request_errors(Errors),
    {error, {invalid, FormattedErrors}};
process_result({exception, #stat_BadToken{reason = Reason}}) ->
    {error, {bad_token, Reason}}.

get_time(Key, Req) ->
    case genlib_map:get(Key, Req) of
        Timestamp when is_binary(Timestamp) ->
            wapi_utils:to_universal_time(Timestamp);
        undefined ->
            undefined
    end.

merge_and_compact(M1, M2) ->
    genlib_map:compact(maps:merge(M1, M2)).

format_request_errors([]) -> <<>>;
format_request_errors(Errors) -> genlib_string:join(<<"\n">>, Errors).

-spec unmarshal_response
    (withdrawals, fistful_stat_thrift:'StatWithdrawal'()) -> map();
    (deposits, fistful_stat_thrift:'StatDeposit'()) -> map();
    (wallets, fistful_stat_thrift:'StatWallet'()) -> map();
    (destinations, fistful_stat_thrift:'StatDestination'()) -> map();
    (identities, fistful_stat_thrift:'StatIdentity'()) -> map();
    (deposit_reverts, fistful_stat_thrift:'StatDepositRevert'()) -> map();
    (deposit_adjustments, fistful_stat_thrift:'StatDepositAdjustment'()) -> map().
unmarshal_response(withdrawals, Response) ->
    merge_and_compact(
        #{
            <<"id">> => Response#stat_StatWithdrawal.id,
            <<"createdAt">> => Response#stat_StatWithdrawal.created_at,
            <<"wallet">> => Response#stat_StatWithdrawal.source_id,
            <<"destination">> => Response#stat_StatWithdrawal.destination_id,
            <<"externalID">> => Response#stat_StatWithdrawal.external_id,
            <<"body">> => unmarshal_cash(
                Response#stat_StatWithdrawal.amount,
                Response#stat_StatWithdrawal.currency_symbolic_code
            ),
            <<"fee">> => unmarshal_cash(
                Response#stat_StatWithdrawal.fee,
                Response#stat_StatWithdrawal.currency_symbolic_code
            )
        },
        unmarshal_withdrawal_stat_status(Response#stat_StatWithdrawal.status)
    );
unmarshal_response(deposits, Response) ->
    merge_and_compact(
        #{
            <<"id">> => Response#stat_StatDeposit.id,
            <<"createdAt">> => Response#stat_StatDeposit.created_at,
            <<"wallet">> => Response#stat_StatDeposit.destination_id,
            <<"source">> => Response#stat_StatDeposit.source_id,
            <<"body">> => unmarshal_cash(
                Response#stat_StatDeposit.amount,
                Response#stat_StatDeposit.currency_symbolic_code
            ),
            <<"fee">> => unmarshal_cash(
                Response#stat_StatDeposit.fee,
                Response#stat_StatDeposit.currency_symbolic_code
            ),
            <<"revertStatus">> => unmarshal_revert_status(Response#stat_StatDeposit.revert_status),
            <<"desc">> => Response#stat_StatDeposit.description
        },
        unmarshal_deposit_stat_status(Response#stat_StatDeposit.status)
    );
unmarshal_response(wallets, Response) ->
    genlib_map:compact(#{
        <<"id">> => Response#stat_StatWallet.id,
        <<"name">> => Response#stat_StatWallet.name,
        <<"identity">> => Response#stat_StatWallet.identity_id,
        <<"createdAt">> => Response#stat_StatWallet.created_at,
        <<"currency">> => Response#stat_StatWallet.currency_symbolic_code
    });
unmarshal_response(destinations, Response) ->
    genlib_map:compact(#{
        <<"id">> => Response#stat_StatDestination.id,
        <<"name">> => Response#stat_StatDestination.name,
        <<"createdAt">> => Response#stat_StatDestination.created_at,
        <<"isBlocked">> => Response#stat_StatDestination.is_blocked,
        <<"identity">> => Response#stat_StatDestination.identity,
        <<"currency">> => Response#stat_StatDestination.currency_symbolic_code,
        <<"resource">> => unmarshal_resource(Response#stat_StatDestination.resource),
        <<"status">> => unmarshal_destination_stat_status(Response#stat_StatDestination.status),
        <<"externalID">> => Response#stat_StatDestination.external_id
    });
unmarshal_response(identities, Response) ->
    genlib_map:compact(#{
        <<"id">> => Response#stat_StatIdentity.id,
        <<"name">> => Response#stat_StatIdentity.name,
        <<"createdAt">> => Response#stat_StatIdentity.created_at,
        <<"provider">> => Response#stat_StatIdentity.provider,
        <<"isBlocked">> => Response#stat_StatIdentity.is_blocked,
        <<"externalID">> => Response#stat_StatIdentity.external_id
    });
unmarshal_response(deposit_reverts, Response) ->
    merge_and_compact(
        #{
            <<"id">> => Response#stat_StatDepositRevert.id,
            <<"depositId">> => Response#stat_StatDepositRevert.deposit_id,
            <<"wallet">> => Response#stat_StatDepositRevert.wallet_id,
            <<"source">> => Response#stat_StatDepositRevert.source_id,
            <<"body">> => unmarshal_cash(Response#stat_StatDepositRevert.body),
            <<"createdAt">> => Response#stat_StatDepositRevert.created_at,
            <<"reason">> => Response#stat_StatDepositRevert.reason,
            <<"externalId">> => Response#stat_StatDepositRevert.external_id
        },
        unmarshal_status(Response#stat_StatDepositRevert.status)
    );
unmarshal_response(deposit_adjustments, Response) ->
    merge_and_compact(
        #{
            <<"id">> => Response#stat_StatDepositAdjustment.id,
            <<"depositId">> => Response#stat_StatDepositAdjustment.deposit_id,
            <<"changesPlan">> => unmarshal_changes_plan(Response#stat_StatDepositAdjustment.changes_plan),
            <<"createdAt">> => Response#stat_StatDepositAdjustment.created_at,
            <<"externalId">> => Response#stat_StatDepositAdjustment.external_id
        },
        unmarshal_status(Response#stat_StatDepositAdjustment.status)
    ).

unmarshal_status({pending, _}) ->
    #{<<"status">> => <<"Pending">>};
unmarshal_status({succeeded, _}) ->
    #{<<"status">> => <<"Succeeded">>};
unmarshal_status({failed, _}) ->
    #{
        <<"status">> => <<"Failed">>,
        <<"failure">> => #{<<"code">> => <<"failed">>}
    }.

unmarshal_revert_status(undefined) ->
    undefined;
unmarshal_revert_status(none) ->
    <<"None"/utf8>>;
unmarshal_revert_status(partial) ->
    <<"Partial"/utf8>>;
unmarshal_revert_status(full) ->
    <<"Full"/utf8>>.

unmarshal_changes_plan(#stat_DepositAdjustmentChangesPlan{new_cash = Cash, new_status = Status}) ->
    maps:merge(#{<<"cash">> => unmarshal_cash_change_plan(Cash)}, unmarshal_status_change_plan(Status)).

unmarshal_cash_change_plan(undefined) ->
    #{};
unmarshal_cash_change_plan(#stat_DepositAdjustmentCashChangePlan{
    amount = Amount,
    fee = Fee,
    provider_fee = ProviderFee
}) ->
    #{
        <<"amount">> => unmarshal_cash(Amount),
        <<"fee">> => unmarshal_cash(Fee),
        <<"providerFee">> => unmarshal_cash(ProviderFee)
    }.

unmarshal_status_change_plan(undefined) ->
    #{};
unmarshal_status_change_plan(#stat_DepositAdjustmentStatusChangePlan{new_status = Status}) ->
    unmarshal_status(Status).

unmarshal_destination_stat_status(undefined) ->
    undefined;
unmarshal_destination_stat_status({unauthorized, _}) ->
    <<"Unauthorized">>;
unmarshal_destination_stat_status({authorized, _}) ->
    <<"Authorized">>.

unmarshal_cash(Amount, Currency) when is_bitstring(Currency) ->
    #{<<"amount">> => Amount, <<"currency">> => Currency}.

unmarshal_cash(#'fistful_base_Cash'{amount = Amount, currency = Currency}) ->
    unmarshal_cash(Amount, Currency#'fistful_base_CurrencyRef'.symbolic_code).

unmarshal_withdrawal_stat_status({failed, #stat_WithdrawalFailed{base_failure = BaseFailure}}) ->
    wapi_codec:convert(withdrawal_status, {failed, BaseFailure});
unmarshal_withdrawal_stat_status(Status) ->
    wapi_codec:convert(withdrawal_status, Status).

unmarshal_deposit_stat_status({pending, #stat_DepositPending{}}) ->
    #{<<"status">> => <<"Pending">>};
unmarshal_deposit_stat_status({succeeded, #stat_DepositSucceeded{}}) ->
    #{<<"status">> => <<"Succeeded">>};
unmarshal_deposit_stat_status({failed, #stat_DepositFailed{failure = _Failure}}) ->
    #{
        <<"status">> => <<"Failed">>,
        <<"failure">> => #{<<"code">> => <<"failed">>}
    }.

unmarshal_resource({bank_card, BankCard}) ->
    unmarshal_bank_card(BankCard);
unmarshal_resource({crypto_wallet, CryptoWallet}) ->
    unmarshal_crypto_wallet(CryptoWallet);
unmarshal_resource({digital_wallet, DigitalWallet}) ->
    unmarshal_digital_wallet(DigitalWallet).

unmarshal_bank_card(#'fistful_base_BankCard'{
    token = Token,
    bin = Bin,
    masked_pan = MaskedPan
}) ->
    genlib_map:compact(#{
        <<"type">> => <<"BankCardDestinationResource">>,
        <<"token">> => Token,
        <<"bin">> => Bin,
        <<"lastDigits">> => wapi_utils:get_last_pan_digits(MaskedPan)
    }).

unmarshal_crypto_wallet(#'fistful_base_CryptoWallet'{
    id = CryptoWalletID,
    currency = #'fistful_base_CryptoCurrencyRef'{id = Currency}
}) ->
    #{
        <<"type">> => <<"CryptoWalletDestinationResource">>,
        <<"id">> => CryptoWalletID,
        <<"currency">> => Currency
    }.

unmarshal_digital_wallet(#'fistful_base_DigitalWallet'{
    id = DigitalWalletID,
    payment_service = #'fistful_base_PaymentServiceRef'{id = Provider},
    account_name = AccountName,
    account_identity_number = AccountIdentityNumber
}) ->
    genlib_map:compact(#{
        <<"type">> => <<"DigitalWalletDestinationResource">>,
        <<"id">> => DigitalWalletID,
        <<"provider">> => Provider,
        <<"accountName">> => AccountName,
        <<"accountIdentityNumber">> => AccountIdentityNumber
    }).
