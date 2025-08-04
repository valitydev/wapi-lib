-module(wapi_domain_backend).

-include_lib("damsel/include/dmsl_domain_thrift.hrl").
-include_lib("damsel/include/dmsl_domain_conf_v2_thrift.hrl").

-type response_data() :: wapi_handler_utils:response_data().

-export([head/0]).
-export([get_currency/1]).
-export([get_party_config/1]).
-export([get_object/1]).
-export([get_object/2]).

%%

-type id() :: binary().
-type object_data() :: any().

%% Pipeline

-import(wapi_pipeline, [do/1, unwrap/1]).

%%

-spec head() -> dmt_client:vsn().
head() ->
    dmt_client:get_latest_version().

-spec get_party_config(id()) -> {ok, {map(), id()}} | {error, notfound}.
get_party_config(PartyID) ->
    do(fun() ->
        _Party = unwrap(get_object({party_config, #domain_PartyConfigRef{id = PartyID}})),
        {#{<<"id">> => PartyID}, PartyID}
    end).

-spec get_currency(id()) -> {ok, response_data()} | {error, notfound}.
get_currency(ID) ->
    do(fun() ->
        Currency = unwrap(get_object({currency, #domain_CurrencyRef{symbolic_code = ID}})),
        #{
            <<"id">> => genlib_string:to_upper(genlib:to_binary(ID)),
            <<"name">> => Currency#domain_Currency.name,
            <<"numericCode">> => genlib:to_binary(Currency#domain_Currency.numeric_code),
            <<"exponent">> => Currency#domain_Currency.exponent
        }
    end).

-spec get_object(dmt_client:object_ref()) -> {ok, object_data()} | {error, notfound}.
get_object(ObjectRef) ->
    get_object(latest, ObjectRef).

-spec get_object(dmt_client:version(), dmt_client:object_ref()) -> {ok, object_data()} | {error, notfound}.
get_object(Ref, {Type, ObjectRef}) ->
    try dmt_client:checkout_object(Ref, {Type, ObjectRef}) of
        #domain_conf_v2_VersionedObject{object = {Type, {_, ObjectRef, ObjectData}}} ->
            {ok, ObjectData}
    catch
        #domain_conf_v2_ObjectNotFound{} ->
            {error, notfound}
    end.
