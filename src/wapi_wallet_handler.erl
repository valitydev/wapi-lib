-module(wapi_wallet_handler).

-export([prepare/4]).

%% Types

-type request_data() :: #{atom() | binary() => term()}.
-type status_code() :: 200..599.
-type headers() :: cowboy:http_headers().
-type response_data() :: map() | [map()] | undefined.
-type response() :: {status_code(), headers(), response_data()}.
-type request_result() :: {ok | error, response()}.
-type request_state() :: #{
    authorize := fun(() -> {ok, wapi_auth:resolution()} | request_result()),
    process := fun(() -> request_result())
}.

-type operation_id() :: atom().
-type swag_schema() :: map().
-type operation_spec() :: map().
-type swag_server_get_schema_fun() :: fun(() -> swag_schema()).
-type swag_server_get_operation_fun() :: fun((operation_id()) -> operation_spec()).

-type client_peer() :: #{
    ip_address => IP :: inet:ip_address(),
    port_number => Port :: inet:port_number()
}.
-type auth_context() :: any().
-type req() :: cowboy_req:req().
-type request_context() :: #{
    auth_context => AuthContext :: auth_context(),
    peer => client_peer(),
    cowboy_req => req()
}.

-type handler_opts() :: _.
-type handler_context() :: #{
    operation_id := operation_id(),
    woody_context := woody_context:ctx(),
    swagger_context := request_context(),
    swag_server_get_schema_fun := swag_server_get_schema_fun(),
    swag_server_get_operation_fun := swag_server_get_operation_fun()
}.

-export_type([request_data/0]).
-export_type([request_result/0]).

-export_type([handler_opts/0]).
-export_type([status_code/0]).
-export_type([headers/0]).
-export_type([response_data/0]).
-export_type([request_context/0]).
-export_type([operation_id/0]).
-export_type([handler_context/0]).
-export_type([swag_server_get_schema_fun/0]).
-export_type([swag_server_get_operation_fun/0]).

respond_if_forbidden(forbidden, Response) ->
    Response;
respond_if_forbidden(allowed, _Response) ->
    allowed.

mask_notfound(Resolution) ->
    % ED-206
    % When bouncer says "forbidden" we can't really tell the difference between "forbidden because
    % of no such invoice", "forbidden because client has no access to it" and "forbidden because
    % client has no permission to act on it". From the point of view of existing integrations this
    % is not great, so we have to mask specific instances of missing authorization as if specified
    % invoice is nonexistent.
    respond_if_forbidden(Resolution, wapi_handler_utils:reply_ok(404)).

%% Providers
-spec prepare(operation_id(), request_data(), handler_context(), handler_opts()) -> {ok, request_state()}.

%% Wallets
prepare('GetWallet' = OperationID, #{'walletID' := WalletID}, Context, _Opts) ->
    {ResultWallet, ResultWalletOwner} =
        case wapi_wallet_backend:get(WalletID, Context) of
            {ok, Wallet, Owner} -> {Wallet, Owner};
            {error, {wallet, notfound}} -> {undefined, undefined}
        end,
    Authorize = fun() ->
        Prototypes = [
            {operation, #{wallet => WalletID, id => OperationID}},
            {wallet, [wapi_bouncer_context:build_wallet_entity(wallet, ResultWallet, {party, ResultWalletOwner})]}
        ],
        Resolution = mask_notfound(wapi_auth:authorize_operation(Prototypes, Context)),
        {ok, Resolution}
    end,
    Process = fun() ->
        wapi_handler_utils:reply_ok(200, ResultWallet)
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare('GetWalletAccount' = OperationID, #{'walletID' := WalletID}, Context, _Opts) ->
    AuthContext = build_auth_context([{wallet, WalletID}], [], Context),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_wallet_backend:get_account(WalletID, Context) of
            {ok, WalletAccount} -> wapi_handler_utils:reply_ok(200, WalletAccount);
            {error, {wallet, notfound}} -> wapi_handler_utils:reply_ok(404)
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
%% Destinations
prepare('ListDestinations' = OperationID, Req0, Context, _Opts) ->
    AuthContext = build_auth_context(
        [wapi_handler_utils:maybe_with('partyID', Req0, fun(PartyID) -> {party, PartyID} end)],
        [],
        Context
    ),
    {Req, PartyID} = patch_party_req(Context, Req0),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{party => PartyID, id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_stat_backend:list_destinations(Req, Context) of
            {ok, StatResult} ->
                wapi_handler_utils:reply_ok(200, StatResult);
            {error, {invalid, Errors}} ->
                wapi_handler_utils:reply_ok(400, #{
                    <<"errorType">> => <<"NoMatch">>,
                    <<"description">> => Errors
                });
            {error, {bad_token, Reason}} ->
                wapi_handler_utils:reply_ok(400, #{
                    <<"errorType">> => <<"InvalidToken">>,
                    <<"description">> => Reason
                })
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare('GetDestination' = OperationID, #{'destinationID' := DestinationID}, Context, _Opts) ->
    {ResultDestination, ResultDestinationOwner} =
        case wapi_destination_backend:get(DestinationID, Context) of
            {ok, Destination, Owner} -> {Destination, Owner};
            {error, {destination, notfound}} -> {undefined, undefined}
        end,
    Authorize = fun() ->
        Prototypes = [
            {
                operation,
                #{destination => DestinationID, id => OperationID}
            },
            {wallet, [
                wapi_bouncer_context:build_wallet_entity(
                    destination,
                    ResultDestination,
                    {party, ResultDestinationOwner}
                )
            ]}
        ],
        Resolution = mask_notfound(wapi_auth:authorize_operation(Prototypes, Context)),
        {ok, Resolution}
    end,
    Process = fun() ->
        wapi_handler_utils:reply_ok(200, ResultDestination)
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare('GetDestinationByExternalID' = OperationID, #{'externalID' := ExternalID}, Context, _Opts) ->
    {ResultDestination, ResultDestinationOwner, DestinationID} =
        case wapi_destination_backend:get_by_external_id(ExternalID, Context) of
            {ok, Wallet = #{<<"id">> := ID}, Owner} -> {Wallet, Owner, ID};
            {error, {destination, notfound}} -> {undefined, undefined, undefined};
            {error, {external_id, {unknown_external_id, ExternalID}}} -> {undefined, undefined, undefined}
        end,
    Authorize = fun() ->
        Prototypes = [
            {
                operation,
                #{destination => DestinationID, id => OperationID}
            },
            {wallet, [
                wapi_bouncer_context:build_wallet_entity(
                    destination,
                    ResultDestination,
                    {party, ResultDestinationOwner}
                )
            ]}
        ],
        Resolution = mask_notfound(wapi_auth:authorize_operation(Prototypes, Context)),
        {ok, Resolution}
    end,
    Process = fun() ->
        wapi_handler_utils:reply_ok(200, ResultDestination)
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare(
    'CreateDestination' = OperationID,
    #{'Destination' := Params = #{<<"party">> := PartyID}},
    Context,
    Opts
) ->
    AuthContext = build_auth_context([{party, PartyID}], [], Context),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_destination_backend:create(Params, Context) of
            {ok, Destination = #{<<"id">> := DestinationID}} ->
                wapi_handler_utils:reply_ok(
                    201, Destination, get_location('GetDestination', [DestinationID], Context, Opts)
                );
            {error, {party, notfound}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"No such party">>));
            {error, {currency, notfound}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"Currency not supported">>));
            {error, inaccessible} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"Party inaccessible">>));
            {error, {external_id_conflict, {ID, ExternalID}}} ->
                wapi_handler_utils:logic_error(external_id_conflict, {ID, ExternalID});
            {error, {invalid_resource_token, Type}} ->
                wapi_handler_utils:reply_ok(400, #{
                    <<"errorType">> => <<"InvalidResourceToken">>,
                    <<"name">> => Type,
                    <<"description">> => <<"Specified resource token is invalid">>
                });
            {error, {invalid_generic_resource, {Type, unknown_resource}}} ->
                wapi_handler_utils:reply_ok(400, #{
                    <<"errorType">> => <<"SchemaViolated">>,
                    <<"name">> => Type,
                    <<"description">> => <<"Unknown resource">>
                })
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
%% Withdrawals
prepare('CreateQuote' = OperationID, #{'WithdrawalQuoteParams' := Params}, Context, _Opts) ->
    AuthContext = build_auth_context(
        [
            wapi_handler_utils:maybe_with(<<"destinationID">>, Params, fun(DestinationID) ->
                {destination, DestinationID}
            end),
            {wallet, maps:get(<<"walletID">>, Params)}
        ],
        [],
        Context
    ),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_withdrawal_backend:create_quote(Params, Context) of
            {ok, Quote} ->
                wapi_handler_utils:reply_ok(202, Quote);
            {error, {destination, notfound}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"No such destination">>));
            {error, {party, notfound}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"No such party">>));
            {error, {wallet, notfound}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"No such wallet">>));
            {error, {forbidden_currency, _}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Forbidden currency">>)
                );
            {error, {forbidden_amount, _}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Invalid cash amount">>)
                );
            {error, {invalid_amount, _}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Invalid cash amount">>)
                );
            {error, {inconsistent_currency, _}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Invalid currency">>)
                );
            {error, {realms_mismatch, _}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(
                        <<"This wallet and destination cannot be used together">>
                    )
                );
            {error, {destination_resource, {bin_data, not_found}}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Unknown card issuer">>)
                )
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare('CreateWithdrawal' = OperationID, #{'WithdrawalParameters' := Params}, Context, Opts) ->
    AuthContext = build_auth_context(
        [
            {wallet, maps:get(<<"wallet">>, Params)},
            {destination, maps:get(<<"destination">>, Params)}
        ],
        [],
        Context
    ),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_withdrawal_backend:create(Params, Context) of
            {ok, Withdrawal = #{<<"id">> := WithdrawalID}} ->
                wapi_handler_utils:reply_ok(
                    202, Withdrawal, get_location('GetWithdrawal', [WithdrawalID], Context, Opts)
                );
            {error, {destination, notfound}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"No such destination">>));
            {error, {party, notfound}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"No such party">>));
            {error, {external_id_conflict, ID}} ->
                ExternalID = maps:get(<<"externalID">>, Params, undefined),
                wapi_handler_utils:logic_error(external_id_conflict, {ID, ExternalID});
            {error, {wallet, notfound}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"No such wallet">>));
            {error, {wallet, {inaccessible, _}}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"Wallet inaccessible">>));
            {error, {quote_invalid_party, _}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Withdrawal owner differs from quote`s one">>)
                );
            {error, {quote_invalid_wallet, _}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Withdrawal wallet differs from quote`s one">>)
                );
            {error, {quote, {invalid_destination, _}}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Withdrawal destination differs from quote`s one">>)
                );
            {error, {quote, {invalid_body, _}}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Withdrawal body differs from quote`s one">>)
                );
            {error, {forbidden_currency, _}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Forbidden currency">>)
                );
            {error, {forbidden_amount, _}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Invalid cash amount">>)
                );
            {error, {invalid_amount, _}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Invalid cash amount">>)
                );
            {error, {inconsistent_currency, _}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Invalid currency">>)
                );
            {error, {realms_mismatch, _}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(
                        <<"This wallet and destination cannot be used together">>
                    )
                );
            {error, {destination_resource, {bin_data, not_found}}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Unknown card issuer">>)
                )
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare('GetWithdrawal' = OperationID, #{'withdrawalID' := WithdrawalID}, Context, _Opts) ->
    {ResultWithdrawal, ResultWithdrawalOwner} =
        case wapi_withdrawal_backend:get(WithdrawalID, Context) of
            {ok, Withdrawal, Owner} -> {Withdrawal, Owner};
            {error, {withdrawal, notfound}} -> {undefined, undefined}
        end,
    Authorize = fun() ->
        Prototypes = [
            {
                operation,
                #{withdrawal => WithdrawalID, id => OperationID}
            },
            {wallet, [
                wapi_bouncer_context:build_wallet_entity(withdrawal, ResultWithdrawal, {party, ResultWithdrawalOwner})
            ]}
        ],
        Resolution = mask_notfound(wapi_auth:authorize_operation(Prototypes, Context)),
        {ok, Resolution}
    end,
    Process = fun() ->
        wapi_handler_utils:reply_ok(200, ResultWithdrawal)
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare('GetWithdrawalByExternalID' = OperationID, #{'externalID' := ExternalID}, Context, _Opts) ->
    {ResultWithdrawal, ResultWithdrawalOwner, WithdrawalID} =
        case wapi_withdrawal_backend:get_by_external_id(ExternalID, Context) of
            {ok, Wallet = #{<<"id">> := ID}, Owner} -> {Wallet, Owner, ID};
            {error, {withdrawal, notfound}} -> {undefined, undefined, undefined};
            {error, {external_id, {unknown_external_id, ExternalID}}} -> {undefined, undefined, undefined}
        end,
    Authorize = fun() ->
        Prototypes = [
            {
                operation,
                #{withdrawal => WithdrawalID, id => OperationID}
            },
            {wallet, [
                wapi_bouncer_context:build_wallet_entity(withdrawal, ResultWithdrawal, {party, ResultWithdrawalOwner})
            ]}
        ],
        Resolution = mask_notfound(wapi_auth:authorize_operation(Prototypes, Context)),
        {ok, Resolution}
    end,
    Process = fun() ->
        wapi_handler_utils:reply_ok(200, ResultWithdrawal)
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare('ListWithdrawals' = OperationID, Req0, Context, _Opts) ->
    AuthContext = build_auth_context(
        [
            wapi_handler_utils:maybe_with('partyID', Req0, fun(PartyID) -> {party, PartyID} end),
            wapi_handler_utils:maybe_with('walletID', Req0, fun(WalletID) -> {wallet, WalletID} end),
            wapi_handler_utils:maybe_with('withdrawalID', Req0, fun(WithdrawalID) -> {withdrawal, WithdrawalID} end),
            wapi_handler_utils:maybe_with('destinationID', Req0, fun(DestinationID) -> {destination, DestinationID} end)
        ],
        [],
        Context
    ),
    {Req, PartyID} = patch_party_req(Context, Req0),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{party => PartyID, id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_stat_backend:list_withdrawals(Req, Context) of
            {ok, List} ->
                wapi_handler_utils:reply_ok(200, List);
            {error, {invalid, Errors}} ->
                wapi_handler_utils:reply_ok(400, #{
                    <<"errorType">> => <<"NoMatch">>,
                    <<"description">> => Errors
                });
            {error, {bad_token, Reason}} ->
                wapi_handler_utils:reply_ok(400, #{
                    <<"errorType">> => <<"InvalidToken">>,
                    <<"description">> => Reason
                })
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare('PollWithdrawalEvents' = OperationID, #{'withdrawalID' := WithdrawalID} = Req, Context, _Opts) ->
    AuthContext = build_auth_context([{withdrawal, WithdrawalID}], [], Context),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_withdrawal_backend:get_events(Req, Context) of
            {ok, Events} ->
                wapi_handler_utils:reply_ok(200, Events);
            {error, {withdrawal, notfound}} ->
                wapi_handler_utils:reply_ok(404)
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare(
    'GetWithdrawalEvents' = OperationID,
    #{
        'withdrawalID' := WithdrawalID,
        'eventID' := EventId
    },
    Context,
    _Opts
) ->
    AuthContext = build_auth_context([{withdrawal, WithdrawalID}], [], Context),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_withdrawal_backend:get_event(WithdrawalID, EventId, Context) of
            {ok, Event} ->
                wapi_handler_utils:reply_ok(200, Event);
            {error, {withdrawal, notfound}} ->
                wapi_handler_utils:reply_ok(404);
            {error, {event, notfound}} ->
                wapi_handler_utils:reply_ok(404)
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
%% Deposits
prepare('ListDeposits' = OperationID, Req0, Context, _Opts) ->
    AuthContext = build_auth_context(
        [
            wapi_handler_utils:maybe_with('partyID', Req0, fun(PartyID) -> {party, PartyID} end),
            wapi_handler_utils:maybe_with('walletID', Req0, fun(WalletID) -> {wallet, WalletID} end)
        ],
        [],
        Context
    ),
    {Req, PartyID} = patch_party_req(Context, Req0),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{party => PartyID, id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_stat_backend:list_deposits(Req, Context) of
            {ok, List} ->
                wapi_handler_utils:reply_ok(200, List);
            {error, {invalid, Errors}} ->
                wapi_handler_utils:reply_ok(400, #{
                    <<"errorType">> => <<"NoMatch">>,
                    <<"description">> => Errors
                });
            {error, {bad_token, Reason}} ->
                wapi_handler_utils:reply_ok(400, #{
                    <<"errorType">> => <<"InvalidToken">>,
                    <<"description">> => Reason
                })
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
%% Webhooks
prepare(
    'CreateWebhook' = OperationID,
    #{'Webhook' := #{<<"partyID">> := PartyID, <<"scope">> := Scope}} = Req,
    Context,
    _Opts
) ->
    AuthContext = build_auth_context(
        [
            {party, PartyID},
            wapi_handler_utils:maybe_with(<<"walletID">>, Scope, fun(WalletID) -> {wallet, WalletID} end)
        ],
        [],
        Context
    ),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        {ok, Webhook} = wapi_webhook_backend:create_webhook(Req, Context),
        wapi_handler_utils:reply_ok(201, Webhook)
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare('GetWebhooks' = OperationID, #{'partyID' := PartyID}, Context, _Opts) ->
    AuthContext = build_auth_context([{party, PartyID}], [], Context),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        {ok, Webhooks} = wapi_webhook_backend:get_webhooks(PartyID, Context),
        wapi_handler_utils:reply_ok(200, Webhooks)
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare('GetWebhookByID' = OperationID, #{'partyID' := PartyID, 'webhookID' := WebhookID}, Context, _Opts) ->
    AuthContext = build_auth_context(
        [
            {party, PartyID},
            {webhook, WebhookID}
        ],
        [],
        Context
    ),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_webhook_backend:get_webhook(WebhookID, Context) of
            {ok, Webhook} ->
                wapi_handler_utils:reply_ok(200, Webhook);
            {error, notfound} ->
                wapi_handler_utils:reply_ok(404)
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare(
    'DeleteWebhookByID' = OperationID,
    #{'partyID' := PartyID, 'webhookID' := WebhookID},
    Context,
    _Opts
) ->
    AuthContext = build_auth_context(
        [
            {party, PartyID},
            {webhook, WebhookID}
        ],
        [],
        Context
    ),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_webhook_backend:delete_webhook(WebhookID, Context) of
            ok ->
                wapi_handler_utils:reply_ok(204);
            {error, notfound} ->
                wapi_handler_utils:reply_ok(404)
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
%% Reports
prepare('CreateReport' = OperationID, #{'partyID' := PartyID} = Req, Context, _Opts) ->
    AuthContext = build_auth_context([{party, PartyID}], [], Context),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_report_backend:create_report(Req, Context) of
            {ok, Report} ->
                wapi_handler_utils:reply_ok(201, Report);
            {error, invalid_request} ->
                wapi_handler_utils:reply_ok(400, #{
                    <<"errorType">> => <<"NoMatch">>,
                    <<"name">> => <<"timestamps">>,
                    <<"description">> => <<"invalid time range">>
                });
            {error, {party, notfound}} ->
                wapi_handler_utils:reply_ok(400, #{
                    <<"errorType">> => <<"NotFound">>,
                    <<"name">> => <<"partyID">>,
                    <<"description">> => <<"party not found">>
                })
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare(
    'GetReport' = OperationID,
    #{
        'partyID' := PartyID,
        'reportID' := ReportID
    },
    Context,
    _Opts
) ->
    AuthContext = build_auth_context([{party, PartyID}], [], Context),
    ResultReport =
        case wapi_report_backend:get_report(ReportID, PartyID, Context) of
            {ok, Report} ->
                Report;
            {error, notfound} ->
                undefined
        end,
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{report => ReportID, id => OperationID}, AuthContext)},
            {wallet,
                build_prototype_for(
                    wallet,
                    [wapi_bouncer_context:build_wallet_entity(report, ResultReport, {party, PartyID})],
                    AuthContext
                )}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        wapi_handler_utils:reply_ok(200, ResultReport)
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare('GetReports' = OperationID, #{'partyID' := PartyID} = Req, Context, _Opts) ->
    AuthContext = build_auth_context([{party, PartyID}], [], Context),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_report_backend:get_reports(Req, Context) of
            {ok, ReportList} ->
                wapi_handler_utils:reply_ok(200, ReportList);
            {error, invalid_request} ->
                wapi_handler_utils:reply_ok(400, #{
                    <<"errorType">> => <<"NoMatch">>,
                    <<"name">> => <<"timestamps">>,
                    <<"description">> => <<"invalid time range">>
                });
            {error, {dataset_too_big, Limit}} ->
                wapi_handler_utils:reply_ok(400, #{
                    <<"errorType">> => <<"WrongLength">>,
                    <<"name">> => <<"limitExceeded">>,
                    <<"description">> => io_lib:format("Max limit: ~p", [Limit])
                })
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare('DownloadFile' = OperationID, #{'fileID' := FileId}, Context, _Opts) ->
    Authorize = fun() ->
        Prototypes = [{operation, #{id => OperationID}}],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        ExpiresAt = get_default_url_lifetime(),
        case wapi_report_backend:download_file(FileId, ExpiresAt, Context) of
            {ok, URL} ->
                wapi_handler_utils:reply_ok(201, #{<<"url">> => URL, <<"expiresAt">> => ExpiresAt});
            {error, notfound} ->
                wapi_handler_utils:reply_ok(404)
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
%% Residences
prepare('GetResidence' = OperationID, #{'residence' := ResidenceId}, Context, _Opts) ->
    Authorize = fun() ->
        Prototypes = [{operation, #{id => OperationID}}],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_residence:get(ResidenceId) of
            {ok, Residence} -> wapi_handler_utils:reply_ok(200, Residence);
            {error, notfound} -> wapi_handler_utils:reply_ok(404)
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
%% Currencies
prepare('GetCurrency' = OperationID, #{'currencyID' := CurrencyId}, Context, _Opts) ->
    Authorize = fun() ->
        Prototypes = [{operation, #{id => OperationID}}],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_domain_backend:get_currency(CurrencyId) of
            {ok, Currency} -> wapi_handler_utils:reply_ok(200, Currency);
            {error, notfound} -> wapi_handler_utils:reply_ok(404)
        end
    end,
    {ok, #{authorize => Authorize, process => Process}}.

%% Internal functions
get_location(OperationID, Params, #{swag_server_get_operation_fun := Get}, Opts) ->
    #{path := PathSpec} = Get(OperationID),
    wapi_handler_utils:get_location(PathSpec, Params, Opts).

build_auth_context([], Acc, _Context) ->
    Acc;
build_auth_context([undefined | T], Acc, Context) ->
    build_auth_context(T, Acc, Context);
build_auth_context([H | T], Acc, Context) ->
    AuthContext = build_auth_context(H, Context),
    build_auth_context(T, [AuthContext | Acc], Context).

build_auth_context({party, PartyID}, _Context) ->
    {ResultParty, ResultPartyOwner} =
        case wapi_domain_backend:get_party_config(PartyID) of
            {ok, {PartyConfig, Owner}} -> {PartyConfig, Owner};
            {error, notfound} -> {undefined, undefined}
        end,
    {party, {PartyID, ResultParty, ResultPartyOwner}};
build_auth_context({wallet, WalletID}, Context) ->
    {ResultWallet, ResultWalletOwner} =
        case wapi_wallet_backend:get(WalletID, Context) of
            {ok, Wallet, Owner} -> {Wallet, Owner};
            {error, {wallet, notfound}} -> {undefined, undefined}
        end,
    {wallet, {WalletID, ResultWallet, ResultWalletOwner}};
build_auth_context({destination, DestinationID}, Context) ->
    {ResultDestination, ResultDestinationOwner} =
        case wapi_destination_backend:get(DestinationID, Context) of
            {ok, Destination, Owner} -> {Destination, Owner};
            {error, {destination, notfound}} -> {undefined, undefined}
        end,
    {destination, {DestinationID, ResultDestination, ResultDestinationOwner}};
build_auth_context({withdrawal, WithdrawalID}, Context) ->
    {ResultWithdrawal, ResultWithdrawalOwner} =
        case wapi_withdrawal_backend:get(WithdrawalID, Context) of
            {ok, Withdrawal, Owner} -> {Withdrawal, Owner};
            {error, {withdrawal, notfound}} -> {undefined, undefined}
        end,
    {withdrawal, {WithdrawalID, ResultWithdrawal, ResultWithdrawalOwner}};
build_auth_context({webhook, WebhookID}, Context) ->
    ResultWebhook =
        case wapi_webhook_backend:get_webhook(WebhookID, Context) of
            {ok, Webhook} -> Webhook;
            {error, notfound} -> undefined
        end,
    {webhook, {WebhookID, ResultWebhook}}.

build_prototype_for(operation, OpContext, AuthContext) ->
    lists:foldl(
        fun
            ({party, {PartyID, _Identity, _Owner}}, Acc) ->
                Acc#{party => PartyID};
            ({wallet, {WalletID, _Wallet, _Owner}}, Acc) ->
                Acc#{wallet => WalletID};
            ({destination, {DestinationID, _Destination, _Owner}}, Acc) ->
                Acc#{destination => DestinationID};
            ({withdrawal, {WithdrawalID, _Withdrawal, _Owner}}, Acc) ->
                Acc#{withdrawal => WithdrawalID};
            ({webhook, {WebhookID, _ResultWebhook}}, Acc) ->
                Acc#{webhook => WebhookID}
        end,
        OpContext,
        AuthContext
    );
build_prototype_for(wallet, Entities, AuthContext) ->
    lists:foldl(
        fun
            ({party, {_IdentityID, Party, Owner}}, Acc) ->
                [wapi_bouncer_context:build_wallet_entity(party, Party, {party, Owner}) | Acc];
            ({wallet, {_WalletID, Wallet, Owner}}, Acc) ->
                [wapi_bouncer_context:build_wallet_entity(wallet, Wallet, {party, Owner}) | Acc];
            ({destination, {_DestinationID, Destination, Owner}}, Acc) ->
                [wapi_bouncer_context:build_wallet_entity(destination, Destination, {party, Owner}) | Acc];
            ({withdrawal, {_WithdrawalID, Withdrawal, Owner}}, Acc) ->
                [wapi_bouncer_context:build_wallet_entity(withdrawal, Withdrawal, {party, Owner}) | Acc];
            ({webhook, {_WebhookID, Webhook}}, Acc) ->
                [wapi_bouncer_context:build_wallet_entity(webhook, Webhook) | Acc]
        end,
        Entities,
        AuthContext
    ).

patch_party_req(_Context, #{'partyID' := PartyID} = Req) when PartyID =/= undefined ->
    {Req, PartyID};
patch_party_req(Context, Req) ->
    PartyID = wapi_handler_utils:get_owner(Context),
    {Req#{'partyID' => PartyID}, PartyID}.

% seconds
-define(DEFAULT_URL_LIFETIME, 60).

get_default_url_lifetime() ->
    Now = erlang:system_time(second),
    Lifetime = application:get_env(wapi_lib, file_storage_url_lifetime, ?DEFAULT_URL_LIFETIME),
    genlib_rfc3339:format(Now + Lifetime, second).
