-module(ff_withdrawal_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("damsel/include/dmsl_accounter_thrift.hrl").

%% Common test API

-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

%% Tests
-export([session_fail_test/1]).
-export([quote_fail_test/1]).
-export([route_not_found_fail_test/1]).
-export([limit_check_fail_test/1]).
-export([create_cashlimit_validation_error_test/1]).
-export([create_withdrawal_currency_validation_error_test/1]).
-export([create_wallet_currency_validation_error_test/1]).
-export([create_destination_currency_validation_error_test/1]).
-export([create_currency_validation_error_test/1]).
-export([create_destination_resource_notfound_test/1]).
-export([create_destination_notfound_test/1]).
-export([create_wallet_notfound_test/1]).
-export([create_ok_test/1]).
-export([unknown_test/1]).

%% Internal types

-type config()         :: ct_helper:config().
-type test_case_name() :: ct_helper:test_case_name().
-type group_name()     :: ct_helper:group_name().
-type test_return()    :: _ | no_return().

%% Macro helpers

-define(final_balance(Amount, Currency), {Amount, {{inclusive, Amount}, {inclusive, Amount}}, Currency}).

%% API

-spec all() -> [test_case_name() | {group, group_name()}].
all() ->
    [{group, default}].

-spec groups() -> [{group_name(), list(), [test_case_name()]}].
groups() ->
    [
        {default, [parallel], [
            session_fail_test,
            quote_fail_test,
            route_not_found_fail_test,
            limit_check_fail_test,
            create_cashlimit_validation_error_test,
            create_withdrawal_currency_validation_error_test,
            create_wallet_currency_validation_error_test,
            create_destination_currency_validation_error_test,
            create_currency_validation_error_test,
            create_destination_resource_notfound_test,
            create_destination_notfound_test,
            create_wallet_notfound_test,
            create_ok_test,
            unknown_test
        ]}
    ].

-spec init_per_suite(config()) -> config().
init_per_suite(C) ->
    ct_helper:makeup_cfg([
        ct_helper:test_case_name(init),
        ct_payment_system:setup()
    ], C).

-spec end_per_suite(config()) -> _.
end_per_suite(C) ->
    ok = ct_payment_system:shutdown(C).

%%

-spec init_per_group(group_name(), config()) -> config().
init_per_group(_, C) ->
    C.

-spec end_per_group(group_name(), config()) -> _.
end_per_group(_, _) ->
    ok.
%%

-spec init_per_testcase(test_case_name(), config()) -> config().
init_per_testcase(Name, C) ->
    C1 = ct_helper:makeup_cfg([ct_helper:test_case_name(Name), ct_helper:woody_ctx()], C),
    ok = ff_woody_ctx:set(ct_helper:get_woody_ctx(C1)),
    C1.

-spec end_per_testcase(test_case_name(), config()) -> _.
end_per_testcase(_Name, _C) ->
    ok = ff_woody_ctx:unset().

%% Tests

-spec session_fail_test(config()) -> test_return().
session_fail_test(C) ->
    Party = create_party(C),
    Currency = <<"RUB">>,
    WithdrawalCash = {100, Currency},
    IdentityID = create_person_identity(Party, C, <<"quote-owner">>),
    WalletID = create_wallet(IdentityID, <<"My wallet">>, Currency, C),
    ok = await_wallet_balance({0, Currency}, WalletID),
    DestinationID = create_destination(IdentityID, undefined, C),
    ok = set_wallet_balance(WithdrawalCash, WalletID),
    WithdrawalID = generate_id(),
    WithdrawalParams = #{
        id => WithdrawalID,
        destination_id => DestinationID,
        wallet_id => WalletID,
        body => WithdrawalCash,
        quote => #{
            cash_from   => {4240, <<"RUB">>},
            cash_to     => {2120, <<"USD">>},
            created_at  => <<"2016-03-22T06:12:27Z">>,
            expires_on  => <<"2016-03-22T06:12:27Z">>,
            quote_data  => #{
                <<"version">> => 1,
                <<"quote_data">> => #{<<"test">> => <<"error">>},
                <<"provider_id">> => 3
            }
        }
    },
    ok = ff_withdrawal_machine:create(WithdrawalParams, ff_ctx:new()),
    Result = await_final_withdrawal_status(WithdrawalID),
    ?assertMatch({failed, #{code := <<"test_error">>}}, Result),
    ok = await_wallet_balance(WithdrawalCash, WalletID).

-spec quote_fail_test(config()) -> test_return().
quote_fail_test(C) ->
    Cash = {100, <<"RUB">>},
    #{
        wallet_id := WalletID,
        destination_id := DestinationID
    } = prepare_standard_environment(Cash, C),
    WithdrawalID = generate_id(),
    WithdrawalParams = #{
        id => WithdrawalID,
        destination_id => DestinationID,
        wallet_id => WalletID,
        body => Cash,
        quote => #{
            cash_from   => {4240, <<"RUB">>},
            cash_to     => {2120, <<"USD">>},
            created_at  => <<"2016-03-22T06:12:27Z">>,
            expires_on  => <<"2016-03-22T06:12:27Z">>,
            quote_data  => #{
                <<"version">> => 1,
                <<"quote_data">> => #{<<"test">> => <<"test">>},
                <<"provider_id">> => 10
            }
        }
    },
    ok = ff_withdrawal_machine:create(WithdrawalParams, ff_ctx:new()),
    Result = await_final_withdrawal_status(WithdrawalID),
    ?assertMatch({failed, #{code := <<"unknown">>}}, Result).

-spec route_not_found_fail_test(config()) -> test_return().
route_not_found_fail_test(C) ->
    Cash = {100, <<"RUB">>},
    #{
        wallet_id := WalletID,
        destination_id := DestinationID
    } = prepare_standard_environment(Cash, <<"USD_COUNTRY">>, C),
    WithdrawalID = generate_id(),
    WithdrawalParams = #{
        id => WithdrawalID,
        destination_id => DestinationID,
        wallet_id => WalletID,
        body => Cash
    },
    ok = ff_withdrawal_machine:create(WithdrawalParams, ff_ctx:new()),
    Result = await_final_withdrawal_status(WithdrawalID),
    ?assertMatch({failed, #{code := <<"no_route_found">>}}, Result).

-spec limit_check_fail_test(config()) -> test_return().
limit_check_fail_test(C) ->
    Cash = {100, <<"RUB">>},
    #{
        wallet_id := WalletID,
        destination_id := DestinationID
    } = prepare_standard_environment(Cash, C),
    WithdrawalID = generate_id(),
    WithdrawalParams = #{
        id => WithdrawalID,
        destination_id => DestinationID,
        wallet_id => WalletID,
        body => {200, <<"RUB">>}
    },
    ok = ff_withdrawal_machine:create(WithdrawalParams, ff_ctx:new()),
    Result = await_final_withdrawal_status(WithdrawalID),
    ?assertMatch({failed, #{
        code := <<"account_limit_exceeded">>,
        sub := #{
            code := <<"amount">>
        }
    }}, Result),
    ok = await_wallet_balance(Cash, WalletID).

-spec create_cashlimit_validation_error_test(config()) -> test_return().
create_cashlimit_validation_error_test(C) ->
    Cash = {100, <<"RUB">>},
    #{
        wallet_id := WalletID,
        destination_id := DestinationID
    } = prepare_standard_environment(Cash, C),
    WithdrawalID = generate_id(),
    WithdrawalParams = #{
        id => WithdrawalID,
        destination_id => DestinationID,
        wallet_id => WalletID,
        body => {20000000, <<"RUB">>}
    },
    Result = ff_withdrawal_machine:create(WithdrawalParams, ff_ctx:new()),
    CashRange = {{inclusive, {0, <<"RUB">>}}, {exclusive, {10000001, <<"RUB">>}}},
    Details = {terms_violation, {cash_range, {{20000000, <<"RUB">>}, CashRange}}},
    ?assertMatch({error, {terms, Details}}, Result).

-spec create_withdrawal_currency_validation_error_test(config()) -> test_return().
create_withdrawal_currency_validation_error_test(C) ->
    Cash = {100, <<"USD">>},
    #{
        wallet_id := WalletID,
        destination_id := DestinationID
    } = prepare_standard_environment(Cash, C),
    WithdrawalID = generate_id(),
    WithdrawalParams = #{
        id => WithdrawalID,
        destination_id => DestinationID,
        wallet_id => WalletID,
        body => Cash
    },
    Result = ff_withdrawal_machine:create(WithdrawalParams, ff_ctx:new()),
    Details = {
        <<"USD">>,
        [
            #domain_CurrencyRef{symbolic_code = <<"RUB">>}
        ]
    },
    ?assertMatch({error, {terms, {terms_violation, {not_allowed_currency, Details}}}}, Result).

-spec create_wallet_currency_validation_error_test(config()) -> test_return().
create_wallet_currency_validation_error_test(C) ->
    Cash = {100, <<"RUB">>},
    #{
        wallet_id := WalletID,
        destination_id := DestinationID
    } = prepare_standard_environment(Cash, C),
    WithdrawalID = generate_id(),
    WithdrawalParams = #{
        id => WithdrawalID,
        destination_id => DestinationID,
        wallet_id => WalletID,
        body => {100, <<"USD">>}
    },
    Result = ff_withdrawal_machine:create(WithdrawalParams, ff_ctx:new()),
    ?assertMatch({error, {terms, {invalid_withdrawal_currency, <<"USD">>, {wallet_currency, <<"RUB">>}}}}, Result).

-spec create_destination_currency_validation_error_test(config()) -> test_return().
create_destination_currency_validation_error_test(C) ->
    Cash = {100, <<"RUB">>},
    #{
        wallet_id := WalletID,
        destination_id := DestinationID
    } = prepare_standard_environment(Cash, <<"USD_CURRENCY">>, C),
    WithdrawalID = generate_id(),
    WithdrawalParams = #{
        id => WithdrawalID,
        destination_id => DestinationID,
        wallet_id => WalletID,
        body => {100, <<"RUB">>}
    },
    Result = ff_withdrawal_machine:create(WithdrawalParams, ff_ctx:new()),
    ?assertMatch({error, {inconsistent_currency, {<<"RUB">>, <<"RUB">>, <<"USD">>}}}, Result).

-spec create_currency_validation_error_test(config()) -> test_return().
create_currency_validation_error_test(C) ->
    Cash = {100, <<"RUB">>},
    #{
        wallet_id := WalletID,
        destination_id := DestinationID
    } = prepare_standard_environment(Cash, C),
    WithdrawalID = generate_id(),
    WithdrawalParams = #{
        id => WithdrawalID,
        destination_id => DestinationID,
        wallet_id => WalletID,
        body => {100, <<"EUR">>}
    },
    Result = ff_withdrawal_machine:create(WithdrawalParams, ff_ctx:new()),
    Details = {
        <<"EUR">>,
        [
            #domain_CurrencyRef{symbolic_code = <<"RUB">>},
            #domain_CurrencyRef{symbolic_code = <<"USD">>}
        ]
    },
    ?assertMatch({error, {terms, {terms_violation, {not_allowed_currency, Details}}}}, Result).

-spec create_destination_resource_notfound_test(config()) -> test_return().
create_destination_resource_notfound_test(C) ->
    Cash = {100, <<"RUB">>},
    #{
        wallet_id := WalletID,
        destination_id := DestinationID
    } = prepare_standard_environment(Cash, <<"TEST_NOTFOUND">>, C),
    WithdrawalID = generate_id(),
    WithdrawalParams = #{
        id => WithdrawalID,
        destination_id => DestinationID,
        wallet_id => WalletID,
        body => Cash
    },
    Result = ff_withdrawal_machine:create(WithdrawalParams, ff_ctx:new()),
    ?assertMatch({error, {destination_resource, {bin_data, not_found}}}, Result).

-spec create_destination_notfound_test(config()) -> test_return().
create_destination_notfound_test(C) ->
    Cash = {100, <<"RUB">>},
    #{
        wallet_id := WalletID
    } = prepare_standard_environment(Cash, C),
    WithdrawalID = generate_id(),
    WithdrawalParams = #{
        id => WithdrawalID,
        destination_id => <<"unknown_destination">>,
        wallet_id => WalletID,
        body => Cash
    },
    Result = ff_withdrawal_machine:create(WithdrawalParams, ff_ctx:new()),
    ?assertMatch({error, {destination, notfound}}, Result).

-spec create_wallet_notfound_test(config()) -> test_return().
create_wallet_notfound_test(C) ->
    Cash = {100, <<"RUB">>},
    #{
        destination_id := DestinationID
    } = prepare_standard_environment(Cash, C),
    WithdrawalID = generate_id(),
    WithdrawalParams = #{
        id => WithdrawalID,
        destination_id => DestinationID,
        wallet_id => <<"unknown_wallet">>,
        body => Cash
    },
    Result = ff_withdrawal_machine:create(WithdrawalParams, ff_ctx:new()),
    ?assertMatch({error, {wallet, notfound}}, Result).

-spec create_ok_test(config()) -> test_return().
create_ok_test(C) ->
    Cash = {100, <<"RUB">>},
    #{
        wallet_id := WalletID,
        destination_id := DestinationID
    } = prepare_standard_environment(Cash, C),
    WithdrawalID = generate_id(),
    WithdrawalParams = #{
        id => WithdrawalID,
        destination_id => DestinationID,
        wallet_id => WalletID,
        body => Cash,
        external_id => WithdrawalID
    },
    ok = ff_withdrawal_machine:create(WithdrawalParams, ff_ctx:new()),
    succeeded = await_final_withdrawal_status(WithdrawalID),
    ok = await_wallet_balance({0, <<"RUB">>}, WalletID),
    Withdrawal = get_withdrawal(WithdrawalID),
    WalletID = ff_withdrawal:wallet_id(Withdrawal),
    DestinationID = ff_withdrawal:destination_id(Withdrawal),
    Cash = ff_withdrawal:body(Withdrawal),
    WithdrawalID = ff_withdrawal:external_id(Withdrawal).

-spec unknown_test(config()) -> test_return().
unknown_test(_C) ->
    WithdrawalID = <<"unknown_withdrawal">>,
    Result = ff_withdrawal_machine:get(WithdrawalID),
    ?assertMatch({error, {unknown_withdrawal, WithdrawalID}}, Result).

%% Utils

prepare_standard_environment(WithdrawalCash, C) ->
    prepare_standard_environment(WithdrawalCash, undefined, C).

prepare_standard_environment({_Amount, Currency} = WithdrawalCash, Token, C) ->
    Party = create_party(C),
    IdentityID = create_person_identity(Party, C),
    WalletID = create_wallet(IdentityID, <<"My wallet">>, Currency, C),
    ok = await_wallet_balance({0, Currency}, WalletID),
    DestinationID = create_destination(IdentityID, Token, C),
    ok = set_wallet_balance(WithdrawalCash, WalletID),
    #{
        identity_id => IdentityID,
        party_id => Party,
        wallet_id => WalletID,
        destination_id => DestinationID
    }.

get_withdrawal(WithdrawalID) ->
    {ok, Machine} = ff_withdrawal_machine:get(WithdrawalID),
    ff_withdrawal_machine:withdrawal(Machine).

get_withdrawal_status(WithdrawalID) ->
    ff_withdrawal:status(get_withdrawal(WithdrawalID)).

await_final_withdrawal_status(WithdrawalID) ->
    finished = ct_helper:await(
        finished,
        fun () ->
            {ok, Machine} = ff_withdrawal_machine:get(WithdrawalID),
            Withdrawal = ff_withdrawal_machine:withdrawal(Machine),
            case ff_withdrawal:is_finished(Withdrawal) of
                false ->
                    {not_finished, Withdrawal};
                true ->
                    finished
            end
        end,
        genlib_retry:linear(10, 1000)
    ),
    get_withdrawal_status(WithdrawalID).

create_party(_C) ->
    ID = genlib:bsuuid(),
    _ = ff_party:create(ID),
    ID.

create_person_identity(Party, C) ->
    create_person_identity(Party, C, <<"good-one">>).

create_person_identity(Party, C, ProviderID) ->
    create_identity(Party, ProviderID, <<"person">>, C).

create_identity(Party, ProviderID, ClassID, _C) ->
    ID = genlib:unique(),
    ok = ff_identity_machine:create(
        ID,
        #{party => Party, provider => ProviderID, class => ClassID},
        ff_ctx:new()
    ),
    ID.

create_wallet(IdentityID, Name, Currency, _C) ->
    ID = genlib:unique(),
    ok = ff_wallet_machine:create(
        ID,
        #{identity => IdentityID, name => Name, currency => Currency},
        ff_ctx:new()
    ),
    ID.

await_wallet_balance({Amount, Currency}, ID) ->
    Balance = {Amount, {{inclusive, Amount}, {inclusive, Amount}}, Currency},
    Balance = ct_helper:await(
        Balance,
        fun () -> get_wallet_balance(ID) end,
        genlib_retry:linear(3, 500)
    ),
    ok.

get_wallet_balance(ID) ->
    {ok, Machine} = ff_wallet_machine:get(ID),
    get_account_balance(ff_wallet:account(ff_wallet_machine:wallet(Machine))).

get_account_balance(Account) ->
    {ok, {Amounts, Currency}} = ff_transaction:balance(ff_account:accounter_account_id(Account)),
    {ff_indef:current(Amounts), ff_indef:to_range(Amounts), Currency}.

generate_id() ->
    ff_id:generate_snowflake_id().

create_destination(IID, <<"USD_CURRENCY">>, C) ->
    create_destination(IID, <<"USD">>, undefined, C);
create_destination(IID, Token, C) ->
    create_destination(IID, <<"RUB">>, Token, C).

create_destination(IID, Currency, Token, C) ->
    ID = generate_id(),
    StoreSource = ct_cardstore:bank_card(<<"4150399999000900">>, {12, 2025}, C),
    NewStoreResource = case Token of
        undefined ->
            StoreSource;
        Token ->
            StoreSource#{token => Token}
        end,
    Resource = {bank_card, NewStoreResource},
    Params = #{identity => IID, name => <<"XDesination">>, currency => Currency, resource => Resource},
    ok = ff_destination:create(ID, Params, ff_ctx:new()),
    authorized = ct_helper:await(
        authorized,
        fun () ->
            {ok, Machine} = ff_destination:get_machine(ID),
            ff_destination:status(ff_destination:get(Machine))
        end
    ),
    ID.

set_wallet_balance({Amount, Currency}, ID) ->
    TransactionID = generate_id(),
    {ok, Machine} = ff_wallet_machine:get(ID),
    Account = ff_wallet:account(ff_wallet_machine:wallet(Machine)),
    AccounterID = ff_account:accounter_account_id(Account),
    {CurrentAmount, _, Currency} = get_account_balance(Account),
    {ok, AnotherAccounterID} = create_account(Currency),
    Postings = [{AnotherAccounterID, AccounterID, {Amount - CurrentAmount, Currency}}],
    {ok, _} = ff_transaction:prepare(TransactionID, Postings),
    {ok, _} = ff_transaction:commit(TransactionID, Postings),
    ok.

create_account(CurrencyCode) ->
    Description = <<"ff_test">>,
    case call_accounter('CreateAccount', [construct_account_prototype(CurrencyCode, Description)]) of
        {ok, Result} ->
            {ok, Result};
        {exception, Exception} ->
            {error, {exception, Exception}}
    end.

construct_account_prototype(CurrencyCode, Description) ->
    #accounter_AccountPrototype{
        currency_sym_code = CurrencyCode,
        description = Description
    }.

call_accounter(Function, Args) ->
    Service = {dmsl_accounter_thrift, 'Accounter'},
    ff_woody_client:call(accounter, {Service, Function, Args}, woody_context:new()).