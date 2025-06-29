-module(wapi_withdrawal_quote).

-include_lib("fistful_proto/include/fistful_fistful_base_thrift.hrl").
-include_lib("fistful_proto/include/fistful_wthd_thrift.hrl").

-export([create_token_payload/4]).
-export([decode_token_payload/1]).

-type token_payload() ::
    integer()
    | binary()
    | float()
    | [token_payload()]
    | #{binary() => token_payload()}.

-export_type([token_payload/0]).

%% Internal types

-type wallet_id() :: binary().
-type destination_id() :: binary() | undefined.
-type party_id() :: binary().
-type quote() :: fistful_wthd_thrift:'Quote'().

%% API

-spec create_token_payload(quote(), wallet_id(), destination_id(), party_id()) -> token_payload().
create_token_payload(Quote, WalletID, DestinationID, PartyID) ->
    do_create_token_payload(encode_quote(Quote), WalletID, DestinationID, PartyID).

do_create_token_payload(Quote, WalletID, DestinationID, PartyID) ->
    genlib_map:compact(#{
        <<"version">> => 2,
        <<"walletID">> => WalletID,
        <<"destinationID">> => DestinationID,
        <<"partyID">> => PartyID,
        <<"quote">> => Quote
    }).

-spec decode_token_payload(token_payload()) ->
    {ok, {quote(), wallet_id(), destination_id(), party_id()}} | {error, token_expired}.
decode_token_payload(#{<<"version">> := 2} = Payload) ->
    #{
        <<"version">> := 2,
        <<"walletID">> := WalletID,
        <<"partyID">> := PartyID,
        <<"quote">> := EncodedQuote
    } = Payload,
    Quote = decode_quote(EncodedQuote),
    DestinationID = maps:get(<<"destinationID">>, Payload, undefined),
    {ok, {Quote, WalletID, DestinationID, PartyID}};
decode_token_payload(#{<<"version">> := 1}) ->
    {error, token_expired}.

%% Internals

-spec encode_quote(quote()) -> token_payload().
encode_quote(Quote) ->
    Type = {struct, struct, {fistful_wthd_thrift, 'Quote'}},
    Bin = wapi_thrift_utils:serialize(Type, Quote),
    base64:encode(Bin).

-spec decode_quote(token_payload()) -> quote().
decode_quote(Encoded) ->
    Type = {struct, struct, {fistful_wthd_thrift, 'Quote'}},
    Bin = base64:decode(Encoded),
    wapi_thrift_utils:deserialize(Type, Bin).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-spec payload_symmetry_test() -> _.

payload_symmetry_test() ->
    PartyID = <<"party">>,
    WalletID = <<"wallet">>,
    DestinationID = <<"destination">>,
    ThriftQuote = #wthd_Quote{
        cash_from = #'fistful_base_Cash'{
            amount = 1000000,
            currency = #'fistful_base_CurrencyRef'{
                symbolic_code = <<"RUB">>
            }
        },
        cash_to = #'fistful_base_Cash'{
            amount = 1,
            currency = #'fistful_base_CurrencyRef'{
                symbolic_code = <<"USD">>
            }
        },
        created_at = <<"1970-01-01T00:00:00.123Z">>,
        expires_on = <<"1970-01-01T00:00:00.321Z">>,
        quote_data = {obj, #{{arr, [{nl, {'msgp_Nil'}}]} => {arr, [{nl, {'msgp_Nil'}}]}}},
        route = #wthd_Route{
            provider_id = 100,
            terminal_id = 2
        },
        resource =
            {bank_card, #'fistful_base_ResourceDescriptorBankCard'{
                bin_data_id = {obj, #{{arr, [{nl, {'msgp_Nil'}}]} => {arr, [{nl, {'msgp_Nil'}}]}}}
            }},
        operation_timestamp = <<"1970-01-01T00:00:00.234Z">>,
        domain_revision = 1
    },
    Payload = create_token_payload(ThriftQuote, WalletID, DestinationID, PartyID),
    {ok, {Decoded, WalletID, DestinationID, PartyID}} = decode_token_payload(Payload),
    ?assertEqual(ThriftQuote, Decoded).

-spec payload_v2_decoding_test() -> _.
payload_v2_decoding_test() ->
    PartyID = <<"party">>,
    WalletID = <<"wallet">>,
    DestinationID = <<"destination">>,
    ExpectedThriftQuote = #wthd_Quote{
        cash_from = #'fistful_base_Cash'{
            amount = 1000000,
            currency = #'fistful_base_CurrencyRef'{
                symbolic_code = <<"RUB">>
            }
        },
        cash_to = #'fistful_base_Cash'{
            amount = 1,
            currency = #'fistful_base_CurrencyRef'{
                symbolic_code = <<"USD">>
            }
        },
        created_at = <<"1970-01-01T00:00:00.123Z">>,
        expires_on = <<"1970-01-01T00:00:00.321Z">>,
        quote_data = {obj, #{{arr, [{nl, {'msgp_Nil'}}]} => {arr, [{nl, {'msgp_Nil'}}]}}},
        route = #wthd_Route{
            provider_id = 1000,
            terminal_id = 2,
            provider_id_legacy = <<"700">>
        },
        resource =
            {bank_card, #'fistful_base_ResourceDescriptorBankCard'{
                bin_data_id = {obj, #{{arr, [{nl, {'msgp_Nil'}}]} => {arr, [{nl, {'msgp_Nil'}}]}}}
            }},
        operation_timestamp = <<"1970-01-01T00:00:00.234Z">>,
        domain_revision = 1
    },
    Payload = #{
        <<"version">> => 2,
        <<"walletID">> => WalletID,
        <<"destinationID">> => DestinationID,
        <<"partyID">> => PartyID,
        <<"quote">> => <<
            "DAABCgABAAAAAAAPQkAMAAILAAEAAAADUlVCAAAMAAIKAAEAAAAAAAAAAQwAAgsAAQAAAANVU"
            "0QAAAsAAwAAABgxOTcwLTAxLTAxVDAwOjAwOjAwLjEyM1oLAAQAAAAYMTk3MC0wMS0wMVQwMD"
            "owMDowMC4zMjFaDAAFDQAHDAwAAAABDwAIDAAAAAEMAAEAAAAPAAgMAAAAAQwAAQAAAAAMAAY"
            "IAAMAAAPoCAAEAAAAAgsAAQAAAAM3MDAADAAHDAABDAABDQAHDAwAAAABDwAIDAAAAAEMAAEA"
            "AAAPAAgMAAAAAQwAAQAAAAAAAAsACAAAABgxOTcwLTAxLTAxVDAwOjAwOjAwLjIzNFoKAAkAA"
            "AAAAAAAAQA="
        >>
    },
    ?assertEqual(
        {ok, {ExpectedThriftQuote, WalletID, DestinationID, PartyID}},
        decode_token_payload(Payload)
    ).

-spec payload_v1_decoding_test() -> _.
payload_v1_decoding_test() ->
    PartyID = <<"party">>,
    WalletID = <<"wallet">>,
    DestinationID = <<"destination">>,
    Payload = #{
        <<"version">> => 1,
        <<"walletID">> => WalletID,
        <<"destinationID">> => DestinationID,
        <<"partyID">> => PartyID,
        <<"cashFrom">> => #{<<"amount">> => 1000000, <<"currency">> => <<"RUB">>},
        <<"cashTo">> => #{<<"amount">> => 1, <<"currency">> => <<"USD">>},
        <<"createdAt">> => <<"1970-01-01T00:00:00.123Z">>,
        <<"expiresOn">> => <<"1970-01-01T00:00:00.321Z">>,
        <<"quoteData">> => #{
            <<"version">> => 1,
            <<"quote_data">> => 6,
            <<"provider_id">> => 1000,
            <<"terminal_id">> => 2,
            <<"resource_id">> => #{<<"bank_card">> => 5},
            <<"timestamp">> => 234,
            <<"domain_revision">> => 1
        }
    },
    ?assertEqual(
        {error, token_expired},
        decode_token_payload(Payload)
    ).

-endif.
