-module(wapi_domain_backend).

-include_lib("damsel/include/dmsl_domain_thrift.hrl").
-include_lib("damsel/include/dmsl_domain_conf_thrift.hrl").

-type response_data() :: wapi_handler_utils:response_data().

-export([get_currency/1]).
-export([get_party_config/1]).
-export([get_wallet_config/1]).

%%

-type id() :: binary().
-type object_data() :: any().

%% Pipeline

-import(wapi_pipeline, [do/1, unwrap/1]).

%%

-spec get_party_config(id()) -> {ok, {map(), id()}} | {error, notfound}.
get_party_config(PartyID) ->
    do(fun() ->
        Party = unwrap(object({party, #domain_PartyConfigRef{id = PartyID}})),
        {#{<<"id">> => Party#domain_PartyConfig.id}, PartyID}
    end).

-spec get_wallet_config(id()) -> {ok, {map(), id()}} | {error, notfound}.
get_wallet_config(WalletID) ->
    do(fun() ->
        Wallet = unwrap(object({wallet, #domain_WalletConfigRef{id = WalletID}})),
        {#{
            <<"id">> => Wallet#domain_WalletConfig.id,
            <<"partyID">> => Wallet#domain_WalletConfig.party_id
        }, Wallet#domain_WalletConfig.party_id}
    end).

-spec get_currency(id()) -> {ok, response_data()} | {error, notfound}.
get_currency(ID) ->
    do(fun() ->
        Currency = unwrap(object({currency, #domain_CurrencyRef{symbolic_code = ID}})),
        #{
            <<"id">> => genlib_string:to_upper(genlib:to_binary(ID)),
            <<"name">> => Currency#domain_Currency.name,
            <<"numericCode">> => genlib:to_binary(Currency#domain_Currency.numeric_code),
            <<"exponent">> => Currency#domain_Currency.exponent
        }
    end).

%%
%% Internal
%%

-spec object(dmt_client:object_ref()) -> {ok, object_data()} | {error, notfound}.
object(ObjectRef) ->
    object(latest, ObjectRef).

-spec object(dmt_client:version(), dmt_client:object_ref()) -> {ok, object_data()} | {error, notfound}.
object(Ref, {Type, ObjectRef}) ->
    try dmt_client:checkout_object(Ref, {Type, ObjectRef}) of
        {Type, {_RecordName, ObjectRef, ObjectData}} ->
            {ok, ObjectData}
    catch
        #domain_conf_ObjectNotFound{} ->
            {error, notfound}
    end.
