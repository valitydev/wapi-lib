-module(wapi_codec).

-include_lib("fistful_proto/include/ff_proto_base_thrift.hrl").
-include_lib("fistful_proto/include/ff_proto_repairer_thrift.hrl").
-include_lib("fistful_proto/include/ff_proto_account_thrift.hrl").
-include_lib("fistful_proto/include/ff_proto_msgpack_thrift.hrl").

-export([unmarshal/2]).
-export([unmarshal/3]).

-export([marshal/2]).
-export([marshal/3]).

%% Types

-type type_name() :: atom() | {list, atom()} | {set, atom()}.
-type codec() :: module().

-type encoded_value() :: encoded_value(any()).
-type encoded_value(T) :: T.

-type decoded_value() :: decoded_value(any()).
-type decoded_value(T) :: T.

-export_type([codec/0]).
-export_type([type_name/0]).
-export_type([encoded_value/0]).
-export_type([encoded_value/1]).
-export_type([decoded_value/0]).
-export_type([decoded_value/1]).

%% Callbacks

-callback unmarshal(type_name(), encoded_value()) -> decoded_value().
-callback marshal(type_name(), decoded_value()) -> encoded_value().

%% API

-spec unmarshal(codec(), type_name(), encoded_value()) -> decoded_value().
unmarshal(Codec, Type, Value) ->
    Codec:unmarshal(Type, Value).

-spec marshal(codec(), type_name(), decoded_value()) -> encoded_value().
marshal(Codec, Type, Value) ->
    Codec:marshal(Type, Value).

%% Generic codec

-spec marshal(type_name(), decoded_value()) -> encoded_value().
marshal({list, T}, V) ->
    [marshal(T, E) || E <- V];
marshal({set, T}, V) ->
    ordsets:from_list([marshal(T, E) || E <- ordsets:to_list(V)]);
marshal(id, V) ->
    marshal(string, V);
marshal(event_id, V) ->
    marshal(integer, V);
marshal(provider_id, V) ->
    marshal(integer, V);
marshal(terminal_id, V) ->
    marshal(integer, V);
marshal(blocking, blocked) ->
    blocked;
marshal(blocking, unblocked) ->
    unblocked;
marshal(account_change, {created, Account}) ->
    {created, marshal(account, Account)};
marshal(account, #{
    id := ID,
    identity := IdentityID,
    currency := CurrencyID,
    accounter_account_id := AAID
}) ->
    #'account_Account'{
        id = marshal(id, ID),
        identity = marshal(id, IdentityID),
        currency = marshal(currency_ref, CurrencyID),
        accounter_account_id = marshal(event_id, AAID)
    };
marshal(resource, {bank_card, #{bank_card := BankCard} = ResourceBankCard}) ->
    {bank_card, #'ResourceBankCard'{
        bank_card = marshal(bank_card, BankCard),
        auth_data = maybe_marshal(bank_card_auth_data, maps:get(auth_data, ResourceBankCard, undefined))
    }};
marshal(resource, {crypto_wallet, #{crypto_wallet := CryptoWallet}}) ->
    {crypto_wallet, #'ResourceCryptoWallet'{
        crypto_wallet = marshal(crypto_wallet, CryptoWallet)
    }};
marshal(resource, {digital_wallet, #{digital_wallet := DigitalWallet}}) ->
    {digital_wallet, #'ResourceDigitalWallet'{
        digital_wallet = marshal(digital_wallet, DigitalWallet)
    }};
marshal(resource_descriptor, {bank_card, BinDataID}) ->
    {bank_card, #'ResourceDescriptorBankCard'{
        bin_data_id = marshal(msgpack, BinDataID)
    }};
marshal(bank_card, BankCard = #{token := Token}) ->
    Bin = maps:get(bin, BankCard, undefined),
    PaymentSystemDeprecated = maps:get(payment_system_deprecated, BankCard, undefined),
    MaskedPan = maps:get(masked_pan, BankCard, undefined),
    BankName = maps:get(bank_name, BankCard, undefined),
    IsoCountryCode = maps:get(iso_country_code, BankCard, undefined),
    CardType = maps:get(card_type, BankCard, undefined),
    ExpDate = maps:get(exp_date, BankCard, undefined),
    CardholderName = maps:get(cardholder_name, BankCard, undefined),
    BinDataID = maps:get(bin_data_id, BankCard, undefined),
    #'BankCard'{
        token = marshal(string, Token),
        bin = marshal(string, Bin),
        masked_pan = marshal(string, MaskedPan),
        bank_name = marshal(string, BankName),
        payment_system_deprecated = maybe_marshal(payment_system_deprecated, PaymentSystemDeprecated),
        issuer_country = maybe_marshal(iso_country_code, IsoCountryCode),
        card_type = maybe_marshal(card_type, CardType),
        exp_date = maybe_marshal(exp_date, ExpDate),
        cardholder_name = maybe_marshal(string, CardholderName),
        bin_data_id = maybe_marshal(msgpack, BinDataID)
    };
marshal(bank_card_auth_data, {session, #{session_id := ID}}) ->
    {session_data, #'SessionAuthData'{
        id = marshal(string, ID)
    }};
marshal(crypto_wallet, #{id := ID, data := Data}) ->
    #'CryptoWallet'{
        id = marshal(string, ID),
        data = marshal(crypto_data, Data),
        currency = marshal(crypto_currency, Data)
    };
marshal(digital_wallet, #{id := ID, data := Data}) ->
    #'DigitalWallet'{
        id = marshal(string, ID),
        data = marshal(digital_data, Data)
    };
marshal(exp_date, {Month, Year}) ->
    #'BankCardExpDate'{
        month = marshal(integer, Month),
        year = marshal(integer, Year)
    };
marshal(crypto_currency, {Currency, _}) ->
    Currency;
marshal(crypto_data, {bitcoin, #{}}) ->
    {bitcoin, #'CryptoDataBitcoin'{}};
marshal(crypto_data, {litecoin, #{}}) ->
    {litecoin, #'CryptoDataLitecoin'{}};
marshal(crypto_data, {bitcoin_cash, #{}}) ->
    {bitcoin_cash, #'CryptoDataBitcoinCash'{}};
marshal(crypto_data, {ethereum, #{}}) ->
    {ethereum, #'CryptoDataEthereum'{}};
marshal(crypto_data, {zcash, #{}}) ->
    {zcash, #'CryptoDataZcash'{}};
marshal(crypto_data, {usdt, #{}}) ->
    {usdt, #'CryptoDataUSDT'{}};
marshal(crypto_data, {ripple, Data}) ->
    {ripple, #'CryptoDataRipple'{
        tag = maybe_marshal(string, maps:get(tag, Data, undefined))
    }};
marshal(digital_data, {webmoney, #{}}) ->
    {webmoney, #'DigitalDataWebmoney'{}};
marshal(payment_system_deprecated, V) when is_atom(V) ->
    V;
marshal(iso_country_code, V) when is_atom(V) ->
    V;
marshal(card_type, V) when is_atom(V) ->
    V;
marshal(cash, {Amount, CurrencyRef}) ->
    #'Cash'{
        amount = marshal(amount, Amount),
        currency = marshal(currency_ref, CurrencyRef)
    };
marshal(currency_ref, CurrencyID) when is_binary(CurrencyID) ->
    #'CurrencyRef'{
        symbolic_code = CurrencyID
    };
marshal(amount, V) ->
    marshal(integer, V);
marshal(event_range, {After, Limit}) ->
    #'EventRange'{
        'after' = maybe_marshal(integer, After),
        limit = maybe_marshal(integer, Limit)
    };
marshal(failure, Failure) ->
    #'Failure'{
        code = marshal(string, wapi_failure:code(Failure)),
        reason = maybe_marshal(string, wapi_failure:reason(Failure)),
        sub = maybe_marshal(sub_failure, wapi_failure:sub_failure(Failure))
    };
marshal(sub_failure, Failure) ->
    #'SubFailure'{
        code = marshal(string, wapi_failure:code(Failure)),
        sub = maybe_marshal(sub_failure, wapi_failure:sub_failure(Failure))
    };
marshal(domain_revision, V) when is_integer(V) ->
    V;
marshal(party_revision, V) when is_integer(V) ->
    V;
marshal(string, V) when is_binary(V) ->
    V;
marshal(integer, V) when is_integer(V) ->
    V;
marshal(bool, V) when is_boolean(V) ->
    V;
marshal(context, Ctx) when is_map(Ctx) ->
    maps:map(fun(_NS, V) -> marshal(msgpack, V) end, Ctx);
marshal(msgpack, V) ->
    wapi_msgpack_codec:marshal(msgpack, V);
% Catch this up in thrift validation
marshal(_, Other) ->
    Other.

-spec unmarshal(type_name(), encoded_value()) -> decoded_value().
unmarshal({list, T}, V) ->
    [marshal(T, E) || E <- V];
unmarshal({set, T}, V) ->
    ordsets:from_list([unmarshal(T, E) || E <- ordsets:to_list(V)]);
unmarshal(id, V) ->
    unmarshal(string, V);
unmarshal(event_id, V) ->
    unmarshal(integer, V);
unmarshal(provider_id, V) ->
    unmarshal(integer, V);
unmarshal(terminal_id, V) ->
    unmarshal(integer, V);
unmarshal(blocking, blocked) ->
    blocked;
unmarshal(blocking, unblocked) ->
    unblocked;
unmarshal(account_change, {created, Account}) ->
    {created, unmarshal(account, Account)};
unmarshal(account, #'account_Account'{
    id = ID,
    identity = IdentityID,
    currency = CurrencyRef,
    accounter_account_id = AAID
}) ->
    #{
        id => unmarshal(id, ID),
        identity => unmarshal(id, IdentityID),
        currency => unmarshal(currency_ref, CurrencyRef),
        accounter_account_id => unmarshal(accounter_account_id, AAID)
    };
unmarshal(accounter_account_id, V) ->
    unmarshal(integer, V);
unmarshal(
    resource,
    {bank_card, #'ResourceBankCard'{
        bank_card = BankCard,
        auth_data = AuthData
    }}
) ->
    {bank_card,
        genlib_map:compact(#{
            bank_card => unmarshal(bank_card, BankCard),
            auth_data => maybe_unmarshal(bank_card_auth_data, AuthData)
        })};
unmarshal(resource, {crypto_wallet, #'ResourceCryptoWallet'{crypto_wallet = CryptoWallet}}) ->
    {crypto_wallet, #{
        crypto_wallet => unmarshal(crypto_wallet, CryptoWallet)
    }};
unmarshal(resource_descriptor, {bank_card, BankCard}) ->
    {bank_card, unmarshal(msgpack, BankCard#'ResourceDescriptorBankCard'.bin_data_id)};
unmarshal(bank_card_auth_data, {session_data, #'SessionAuthData'{id = ID}}) ->
    {session, #{
        session_id => unmarshal(string, ID)
    }};
unmarshal(bank_card, #'BankCard'{
    token = Token,
    bin = Bin,
    masked_pan = MaskedPan,
    bank_name = BankName,
    payment_system_deprecated = PaymentSystemDeprecated,
    issuer_country = IsoCountryCode,
    card_type = CardType,
    bin_data_id = BinDataID,
    exp_date = ExpDate,
    cardholder_name = CardholderName
}) ->
    genlib_map:compact(#{
        token => unmarshal(string, Token),
        payment_system_deprecated => maybe_unmarshal(payment_system_deprecated, PaymentSystemDeprecated),
        bin => maybe_unmarshal(string, Bin),
        masked_pan => maybe_unmarshal(string, MaskedPan),
        bank_name => maybe_unmarshal(string, BankName),
        iso_country_code => maybe_unmarshal(iso_country_code, IsoCountryCode),
        card_type => maybe_unmarshal(card_type, CardType),
        exp_date => maybe_unmarshal(exp_date, ExpDate),
        cardholder_name => maybe_unmarshal(string, CardholderName),
        bin_data_id => maybe_unmarshal(msgpack, BinDataID)
    });
unmarshal(exp_date, #'BankCardExpDate'{
    month = Month,
    year = Year
}) ->
    {unmarshal(integer, Month), unmarshal(integer, Year)};
unmarshal(payment_system_deprecated, V) when is_atom(V) ->
    V;
unmarshal(iso_country_code, V) when is_atom(V) ->
    V;
unmarshal(card_type, V) when is_atom(V) ->
    V;
unmarshal(crypto_wallet, #'CryptoWallet'{
    id = CryptoWalletID,
    currency = CryptoWalletCurrency,
    data = Data
}) ->
    genlib_map:compact(#{
        id => unmarshal(string, CryptoWalletID),
        currency => {CryptoWalletCurrency, unmarshal(crypto_data, Data)}
    });
unmarshal(crypto_data, {ripple, #'CryptoDataRipple'{tag = Tag}}) ->
    genlib_map:compact(#{
        tag => maybe_unmarshal(string, Tag)
    });
unmarshal(crypto_data, _) ->
    #{};
unmarshal(cash, #'Cash'{
    amount = Amount,
    currency = CurrencyRef
}) ->
    {unmarshal(amount, Amount), unmarshal(currency_ref, CurrencyRef)};
unmarshal(currency_ref, #'CurrencyRef'{
    symbolic_code = SymbolicCode
}) ->
    unmarshal(string, SymbolicCode);
unmarshal(amount, V) ->
    unmarshal(integer, V);
unmarshal(failure, Failure) ->
    genlib_map:compact(#{
        code => unmarshal(string, Failure#'Failure'.code),
        reason => maybe_unmarshal(string, Failure#'Failure'.reason),
        sub => maybe_unmarshal(sub_failure, Failure#'Failure'.sub)
    });
unmarshal(sub_failure, Failure) ->
    genlib_map:compact(#{
        code => unmarshal(string, Failure#'SubFailure'.code),
        sub => maybe_unmarshal(sub_failure, Failure#'SubFailure'.sub)
    });
unmarshal(domain_revision, V) when is_integer(V) ->
    V;
unmarshal(party_revision, V) when is_integer(V) ->
    V;
unmarshal(string, V) when is_binary(V) ->
    V;
unmarshal(integer, V) when is_integer(V) ->
    V;
unmarshal(context, Ctx) when is_map(Ctx) ->
    maps:map(fun(_K, V) -> unmarshal(msgpack, V) end, Ctx);
unmarshal(msgpack, V) ->
    wapi_msgpack_codec:unmarshal(msgpack, V);
unmarshal(bool, V) when is_boolean(V) ->
    V.

maybe_unmarshal(_Type, undefined) ->
    undefined;
maybe_unmarshal(Type, Value) ->
    unmarshal(Type, Value).

maybe_marshal(_Type, undefined) ->
    undefined;
maybe_marshal(Type, Value) ->
    marshal(Type, Value).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-spec bank_card_codec_test() -> _.

bank_card_codec_test() ->
    BankCard = #{
        token => <<"token">>,
        payment_system_deprecated => visa,
        bin => <<"12345">>,
        masked_pan => <<"7890">>,
        bank_name => <<"bank">>,
        iso_country_code => zmb,
        card_type => credit_or_debit,
        exp_date => {12, 3456},
        cardholder_name => <<"name">>,
        bin_data_id => #{<<"foo">> => 1}
    },
    Type = {struct, struct, {ff_proto_base_thrift, 'BankCard'}},
    Binary = wapi_thrift_utils:serialize(Type, marshal(bank_card, BankCard)),
    Decoded = wapi_thrift_utils:deserialize(Type, Binary),
    ?assertEqual(BankCard, unmarshal(bank_card, Decoded)).

-endif.
