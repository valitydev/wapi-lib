-module(ff_limit_check_codec).

-behaviour(ff_codec).

-include_lib("fistful_proto/include/ff_proto_limit_check_thrift.hrl").

-export([marshal/2]).
-export([unmarshal/2]).

%% Data transform

-define(to_session_event(SessionID, Payload),
    {session, #{id => SessionID, payload => Payload}}).

%% API

-spec marshal(ff_codec:type_name(), ff_codec:decoded_value()) ->
    ff_codec:encoded_value().

marshal(details, {wallet, WalletDetails}) ->
    {wallet, marshal(wallet_details, WalletDetails)};

marshal(wallet_details, ok) ->
    {ok, #lim_check_WalletOk{}};
marshal(wallet_details, {failed, Details}) ->
    #{expected_range := Range, balance := Balance} = Details,
    {failed, #lim_check_WalletFailed{
        expected = ff_codec:marshal(cash_range, Range),
        balance = ff_codec:marshal(cash, Balance)
    }}.

-spec unmarshal(ff_codec:type_name(), ff_codec:encoded_value()) ->
    ff_codec:decoded_value().

unmarshal(details, {wallet, WalletDetails}) ->
    {wallet, unmarshal(wallet_details, WalletDetails)};

unmarshal(wallet_details, {ok, #lim_check_WalletOk{}}) ->
    ok;
unmarshal(wallet_details, {failed, Details}) ->
    #lim_check_WalletFailed{expected = Range, balance = Balance} = Details,
    {failed, #{
        expected_range => ff_codec:unmarshal(cash_range, Range),
        balance => ff_codec:unmarshal(cash, Balance)
    }}.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-spec test() -> _.

-spec wallet_ok_test() -> _.
wallet_ok_test() ->
    Details = {wallet, ok},
    ?assertEqual(Details, unmarshal(details, (marshal(details, Details)))).

-spec wallet_fail_test() -> _.
wallet_fail_test() ->
    Details = {wallet, {failed, #{
        expected_range => {{exclusive, {1, <<"RUB">>}}, {inclusive, {10, <<"RUB">>}}},
        balance => {0, <<"RUB">>}
    }}},
    ?assertEqual(Details, unmarshal(details, (marshal(details, Details)))).

-endif.