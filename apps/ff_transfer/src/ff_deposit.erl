%%%
%%% Deposit
%%%

-module(ff_deposit).

-type id()          :: ff_transfer_machine:id().
-type source_id()   :: ff_source:id().
-type wallet_id()   :: ff_wallet:id().

-type deposit() :: ff_transfer:transfer(transfer_params()).
-type transfer_params() :: #{
    source_id := source_id(),
    wallet_id := wallet_id(),
    wallet_account := account(),
    source_account := account(),
    wallet_cash_flow_plan := cash_flow_plan()
}.

-type machine() :: ff_transfer_machine:st(transfer_params()).
-type events()  :: ff_transfer_machine:events().
-type event()   :: ff_transfer_machine:event(ff_transfer:event(transfer_params(), route())).
-type route()   :: ff_transfer:route(none()).

-export_type([deposit/0]).
-export_type([machine/0]).
-export_type([transfer_params/0]).
-export_type([events/0]).
-export_type([event/0]).
-export_type([route/0]).

%% ff_transfer_machine behaviour
-behaviour(ff_transfer_machine).
-export([process_transfer/1]).
-export([process_failure/2]).

%% Accessors

-export([wallet_id/1]).
-export([source_id/1]).
-export([id/1]).
-export([body/1]).
-export([status/1]).

%% API
-export([create/3]).
-export([get/1]).
-export([get_machine/1]).
-export([events/2]).

%% Pipeline

-import(ff_pipeline, [do/1, unwrap/1, unwrap/2, valid/2]).

%% Internal types

-type account() :: ff_account:account().
-type process_result() :: {ff_transfer_machine:action(), [event()]}.
-type cash_flow_plan() :: ff_cash_flow:cash_flow_plan().

%% Accessors

-spec wallet_id(deposit())       -> source_id().
-spec source_id(deposit())       -> wallet_id().
-spec id(deposit())              -> ff_transfer:id().
-spec body(deposit())            -> ff_transfer:body().
-spec status(deposit())          -> ff_transfer:status().
-spec params(deposit())          -> transfer_params().

wallet_id(T)        -> maps:get(wallet_id, ff_transfer:params(T)).
source_id(T)       -> maps:get(source_id, ff_transfer:params(T)).
id(T)              -> ff_transfer:id(T).
body(T)            -> ff_transfer:body(T).
status(T)          -> ff_transfer:status(T).
params(T)          -> ff_transfer:params(T).

%%

-define(NS, 'ff/deposit_v1').

-type ctx()    :: ff_ctx:ctx().
-type params() :: #{
    source_id   := ff_source:id(),
    wallet_id   := ff_wallet_machine:id(),
    body        := ff_transaction:body()
}.

-spec create(id(), params(), ctx()) ->
    ok |
    {error,
        {source, notfound | unauthorized} |
        {destination, notfound} |
        {provider, notfound} |
        exists |
        _TransferError
    }.

create(ID, #{source_id := SourceID, wallet_id := WalletID, body := Body}, Ctx) ->
    do(fun() ->
        Source = ff_source:get(unwrap(source, ff_source:get_machine(SourceID))),
        Wallet = ff_wallet_machine:wallet(unwrap(destination, ff_wallet_machine:get(WalletID))),
        ok = unwrap(source, valid(authorized, ff_source:status(Source))),
        Params = #{
            handler     => ?MODULE,
            body        => Body,
            params      => #{
                wallet_id             => WalletID,
                source_id             => SourceID,
                wallet_account        => ff_wallet:account(Wallet),
                source_account        => ff_source:account(Source),
                wallet_cash_flow_plan => #{
                    postings => [
                        #{
                            sender   => {wallet, sender_source},
                            receiver => {wallet, receiver_settlement},
                            volume   => {share, {{1, 1}, operation_amount, default}}
                        }
                    ]
                }
            }
        },
        unwrap(ff_transfer_machine:create(?NS, ID, Params, Ctx))
    end).

-spec get(machine()) ->
    deposit().

get(St) ->
    ff_transfer_machine:transfer(St).

-spec get_machine(id()) ->
    {ok, machine()}       |
    {error, notfound}.

get_machine(ID) ->
    ff_transfer_machine:get(?NS, ID).

-spec events(id(), machinery:range()) ->
    {ok, events()} |
    {error, notfound}.

events(ID, Range) ->
    ff_transfer_machine:events(?NS, ID, Range).

%% ff_transfer_machine behaviour

-spec process_transfer(deposit()) ->
    {ok, process_result()} |
    {error, _Reason}.

process_transfer(Deposit) ->
    Activity = deduce_activity(Deposit),
    do_process_transfer(Activity, Deposit).

-spec process_failure(any(), deposit()) ->
    {ok, process_result()} |
    {error, _Reason}.

process_failure(Reason, Deposit) ->
    ff_transfer:process_failure(Reason, Deposit).

%% Internals

-type activity() ::
    p_transfer_start         |
    finish                   |
    idle                     .

% TODO: Move activity to ff_transfer
-spec deduce_activity(deposit()) ->
    activity().
deduce_activity(Deposit) ->
    Params = #{
        p_transfer => ff_transfer:p_transfer(Deposit),
        status => status(Deposit)
    },
    do_deduce_activity(Params).

do_deduce_activity(#{status := pending, p_transfer := undefined}) ->
    p_transfer_start;
do_deduce_activity(#{status := pending, p_transfer := #{status := prepared}}) ->
    finish_him;
do_deduce_activity(_Other) ->
    idle.

do_process_transfer(p_transfer_start, Deposit) ->
    create_p_transfer(Deposit);
do_process_transfer(finish_him, Deposit) ->
    finish_transfer(Deposit);
do_process_transfer(idle, Deposit) ->
    ff_transfer:process_transfer(Deposit).

-spec create_p_transfer(deposit()) ->
    {ok, process_result()} |
    {error, _Reason}.
create_p_transfer(Deposit) ->
    #{
        wallet_account := WalletAccount,
        source_account := SourceAccount,
        wallet_cash_flow_plan := CashFlowPlan
    } = params(Deposit),
    do(fun () ->
        Constants = #{
            operation_amount => body(Deposit)
        },
        Accounts = #{
            {wallet, sender_source} => SourceAccount,
            {wallet, receiver_settlement} => WalletAccount
        },
        FinalCashFlow = unwrap(cash_flow, ff_cash_flow:finalize(CashFlowPlan, Accounts, Constants)),
        PTransferID = construct_p_transfer_id(id(Deposit)),
        PostingsTransferEvents = unwrap(p_transfer, ff_postings_transfer:create(PTransferID, FinalCashFlow)),
        {continue, [{p_transfer, Ev} || Ev <- PostingsTransferEvents]}
    end).

-spec finish_transfer(deposit()) ->
    {ok, {ff_transfer_machine:action(), [ff_transfer_machine:event(ff_transfer:event())]}} |
    {error, _Reason}.
finish_transfer(_Deposit) ->
    {ok, {continue, [{status_changed, succeeded}]}}.

-spec construct_p_transfer_id(id()) -> id().
construct_p_transfer_id(ID) ->
    <<"ff/deposit/", ID/binary>>.