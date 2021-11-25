-module(wapi_wallet_handler).

-behaviour(swag_server_wallet_logic_handler).
-behaviour(wapi_handler).

%% swag_server_wallet_logic_handler callbacks
-export([map_error/2]).
-export([authorize_api_key/4]).
-export([handle_request/4]).

%% wapi_handler callbacks
-export([prepare/4]).

%% Types

-type req_data() :: wapi_handler:req_data().
-type request_state() :: wapi_handler:request_state().
-type handler_context() :: wapi_handler:context().
-type request_result() :: wapi_handler:request_result().
-type operation_id() :: swag_server_wallet:operation_id().
-type api_key() :: swag_server_wallet:api_key().
-type request_context() :: swag_server_wallet:request_context().
-type handler_opts() :: swag_server_wallet:handler_opts(_).

%% API

-spec map_error(atom(), swag_server_wallet_validation:error()) -> swag_server_wallet:error_reason().
map_error(validation_error, Error) ->
    Type = map_error_type(maps:get(type, Error)),
    Name = genlib:to_binary(maps:get(param_name, Error)),
    Message =
        case maps:get(description, Error, undefined) of
            undefined ->
                <<"Request parameter: ", Name/binary, ", error type: ", Type/binary>>;
            Description ->
                DescriptionBin = genlib:to_binary(Description),
                <<"Request parameter: ", Name/binary, ", error type: ", Type/binary, ", description: ",
                    DescriptionBin/binary>>
        end,
    jsx:encode(#{
        <<"errorType">> => Type,
        <<"name">> => Name,
        <<"description">> => Message
    }).

-spec map_error_type(swag_server_wallet_validation:error_type()) -> binary().
map_error_type(no_match) -> <<"NoMatch">>;
map_error_type(not_found) -> <<"NotFound">>;
map_error_type(not_in_range) -> <<"NotInRange">>;
map_error_type(wrong_length) -> <<"WrongLength">>;
map_error_type(wrong_size) -> <<"WrongSize">>;
map_error_type(schema_violated) -> <<"SchemaViolated">>;
map_error_type(wrong_type) -> <<"WrongType">>;
map_error_type(wrong_array) -> <<"WrongArray">>.

mask_notfound(Resolution) ->
    % ED-206
    % When bouncer says "forbidden" we can't really tell the difference between "forbidden because
    % of no such invoice", "forbidden because client has no access to it" and "forbidden because
    % client has no permission to act on it". From the point of view of existing integrations this
    % is not great, so we have to mask specific instances of missing authorization as if specified
    % invoice is nonexistent.
    wapi_handler:respond_if_forbidden(Resolution, wapi_handler_utils:reply_ok(404)).

-spec authorize_api_key(operation_id(), api_key(), request_context(), handler_opts()) ->
    Result :: false | {true, wapi_auth:preauth_context()}.
authorize_api_key(OperationID, ApiKey, _Context, _HandlerOpts) ->
    %% Since we require the request id field to create a woody context for our trip to token_keeper
    %% it seems it is no longer possible to perform any authorization in this method.
    %% To gain this ability back be would need to rewrite the swagger generator to perform its
    %% request validation checks before this stage.
    %% But since a decent chunk of authorization logic is already defined in the handler function
    %% it is probably easier to move it there in its entirety.
    ok = scoper:add_scope('swag.server', #{api => wallet, operation_id => OperationID}),
    case wapi_auth:preauthorize_api_key(ApiKey) of
        {ok, Context} ->
            {true, Context};
        {error, Error} ->
            _ = logger:info("API Key preauthorization failed for ~p due to ~p", [OperationID, Error]),
            false
    end.

-spec handle_request(swag_server_wallet:operation_id(), req_data(), request_context(), handler_opts()) ->
    request_result().
handle_request(OperationID, Req, SwagContext, Opts) ->
    wapi_handler:handle_request(wallet, OperationID, Req, SwagContext, Opts).

%% Providers
-spec prepare(operation_id(), req_data(), handler_context(), handler_opts()) -> {ok, request_state()} | no_return().
prepare(OperationID = 'ListProviders', #{'residence' := Residence}, Context, _Opts) ->
    Authorize = fun() ->
        Prototypes = [{operation, #{id => OperationID}}],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        Providers = wapi_provider_backend:get_providers(maybe_to_list(Residence), Context),
        wapi_handler_utils:reply_ok(200, Providers)
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare(OperationID = 'GetProvider', #{'providerID' := Id}, Context, _Opts) ->
    Authorize = fun() ->
        Prototypes = [{operation, #{id => OperationID}}],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_provider_backend:get_provider(Id, Context) of
            {ok, Provider} -> wapi_handler_utils:reply_ok(200, Provider);
            {error, notfound} -> wapi_handler_utils:reply_ok(404)
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
%% Identities
prepare(OperationID = 'ListIdentities', Req, Context, _Opts) ->
    Authorize = fun() ->
        %% TODO: Add party as arg to query
        %% https://rbkmoney.atlassian.net/browse/ED-258
        Prototypes = [{operation, #{party => wapi_handler_utils:get_owner(Context), id => OperationID}}],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_stat_backend:list_identities(Req, Context) of
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
prepare(OperationID = 'GetIdentity', #{'identityID' := IdentityId}, Context, _Opts) ->
    {ResultIdentity, ResultOwner} =
        case wapi_identity_backend:get_identity(IdentityId, Context) of
            {ok, Identity, Owner} -> {Identity, Owner};
            {error, {identity, notfound}} -> {undefined, undefined}
        end,
    Authorize = fun() ->
        Prototypes = [
            {operation, #{identity => IdentityId, id => OperationID}},
            {wallet, [wapi_bouncer_context:build_wallet_entity(identity, ResultIdentity, {party, ResultOwner})]}
        ],
        Resolution = mask_notfound(wapi_auth:authorize_operation(Prototypes, Context)),
        {ok, Resolution}
    end,
    Process = fun() ->
        wapi_handler_utils:reply_ok(200, ResultIdentity)
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare(OperationID = 'CreateIdentity', #{'Identity' := Params}, Context, Opts) ->
    Authorize = fun() ->
        PartyID =
            case maps:get(<<"partyID">>, Params, undefined) of
                undefined ->
                    wapi_handler_utils:get_owner(Context);
                ID ->
                    ID
            end,
        Prototypes = [
            {
                operation,
                #{party => PartyID, id => OperationID}
            }
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_identity_backend:create_identity(Params, Context) of
            {ok, Identity = #{<<"id">> := IdentityId}} ->
                wapi_handler_utils:reply_ok(201, Identity, get_location('GetIdentity', [IdentityId], Opts));
            {error, {inaccessible, _}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"Party inaccessible">>));
            {error, {party, notfound}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"Party does not exist">>));
            {error, {provider, notfound}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"No such provider">>));
            {error, {identity_class, notfound}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"No such identity class">>));
            {error, inaccessible} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"Identity inaccessible">>));
            {error, {external_id_conflict, ID}} ->
                wapi_handler_utils:reply_ok(409, #{<<"id">> => ID})
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
%% Wallets
prepare(OperationID = 'ListWallets', Req, Context, _Opts) ->
    AuthContext = build_auth_context(
        [wapi_handler_utils:maybe_with('identityID', Req, fun(IdentityID) -> {identity, IdentityID} end)],
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
        case wapi_stat_backend:list_wallets(Req, Context) of
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
prepare(OperationID = 'GetWallet', #{'walletID' := WalletId}, Context, _Opts) ->
    {ResultWallet, ResultWalletOwner} =
        case wapi_wallet_backend:get(WalletId, Context) of
            {ok, Wallet, Owner} -> {Wallet, Owner};
            {error, {wallet, notfound}} -> {undefined, undefined}
        end,
    Authorize = fun() ->
        Prototypes = [
            {operation, #{wallet => WalletId, id => OperationID}},
            {wallet, [wapi_bouncer_context:build_wallet_entity(wallet, ResultWallet, {party, ResultWalletOwner})]}
        ],
        Resolution = mask_notfound(wapi_auth:authorize_operation(Prototypes, Context)),
        {ok, Resolution}
    end,
    Process = fun() ->
        wapi_handler_utils:reply_ok(200, ResultWallet)
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare(OperationID = 'GetWalletByExternalID', #{externalID := ExternalID}, Context, _Opts) ->
    {ResultWallet, ResultWalletOwner, WalletId} =
        case wapi_wallet_backend:get_by_external_id(ExternalID, Context) of
            {ok, Wallet = #{<<"id">> := ID}, Owner} -> {Wallet, Owner, ID};
            {error, {wallet, notfound}} -> {undefined, undefined, undefined};
            {error, {external_id, {unknown_external_id, ExternalID}}} -> {undefined, undefined, undefined}
        end,
    Authorize = fun() ->
        Prototypes = [
            {
                operation,
                #{wallet => WalletId, id => OperationID}
            },
            {wallet, [wapi_bouncer_context:build_wallet_entity(wallet, ResultWallet, {party, ResultWalletOwner})]}
        ],
        Resolution = mask_notfound(wapi_auth:authorize_operation(Prototypes, Context)),
        {ok, Resolution}
    end,
    Process = fun() ->
        wapi_handler_utils:reply_ok(200, ResultWallet)
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare(OperationID = 'CreateWallet', #{'Wallet' := Params = #{<<"identity">> := IdentityID}}, Context, Opts) ->
    AuthContext = build_auth_context([{identity, IdentityID}], [], Context),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_wallet_backend:create(Params, Context) of
            {ok, Wallet = #{<<"id">> := WalletId}} ->
                wapi_handler_utils:reply_ok(201, Wallet, get_location('GetWallet', [WalletId], Opts));
            {error, {identity, notfound}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"No such identity">>));
            {error, {currency, notfound}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"Currency not supported">>));
            {error, inaccessible} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"Identity inaccessible">>));
            {error, {external_id_conflict, ID}} ->
                wapi_handler_utils:reply_ok(409, #{<<"id">> => ID})
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare(OperationID = 'GetWalletAccount', #{'walletID' := WalletId}, Context, _Opts) ->
    AuthContext = build_auth_context([{wallet, WalletId}], [], Context),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_wallet_backend:get_account(WalletId, Context) of
            {ok, WalletAccount} -> wapi_handler_utils:reply_ok(200, WalletAccount);
            {error, {wallet, notfound}} -> wapi_handler_utils:reply_ok(404)
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare(
    OperationID = 'IssueWalletGrant',
    #{
        'walletID' := WalletId,
        'WalletGrantRequest' := #{<<"validUntil">> := Expiration, <<"asset">> := Asset}
    },
    Context,
    _Opts
) ->
    AuthContext = build_auth_context([{wallet, WalletId}], [], Context),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_backend_utils:issue_grant_token({wallets, WalletId, Asset}, Expiration, Context) of
            {ok, Token} ->
                wapi_handler_utils:reply_ok(201, #{
                    <<"token">> => Token,
                    <<"validUntil">> => Expiration,
                    <<"asset">> => Asset
                });
            {error, expired} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Invalid expiration: already expired">>)
                )
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
%% Destinations
prepare(OperationID = 'ListDestinations', Req, Context, _Opts) ->
    AuthContext = build_auth_context(
        [wapi_handler_utils:maybe_with('identityID', Req, fun(IdentityID) -> {identity, IdentityID} end)],
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
prepare(OperationID = 'GetDestination', #{'destinationID' := DestinationId}, Context, _Opts) ->
    {ResultDestination, ResultDestinationOwner} =
        case wapi_destination_backend:get(DestinationId, Context) of
            {ok, Destination, Owner} -> {Destination, Owner};
            {error, {destination, notfound}} -> {undefined, undefined}
        end,
    Authorize = fun() ->
        Prototypes = [
            {
                operation,
                #{destination => DestinationId, id => OperationID}
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
prepare(OperationID = 'GetDestinationByExternalID', #{'externalID' := ExternalID}, Context, _Opts) ->
    {ResultDestination, ResultDestinationOwner, DestinationId} =
        case wapi_destination_backend:get_by_external_id(ExternalID, Context) of
            {ok, Wallet = #{<<"id">> := ID}, Owner} -> {Wallet, Owner, ID};
            {error, {destination, notfound}} -> {undefined, undefined, undefined};
            {error, {external_id, {unknown_external_id, ExternalID}}} -> {undefined, undefined, undefined}
        end,
    Authorize = fun() ->
        Prototypes = [
            {
                operation,
                #{destination => DestinationId, id => OperationID}
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
    OperationID = 'CreateDestination',
    #{'Destination' := Params = #{<<"identity">> := IdentityID}},
    Context,
    Opts
) ->
    AuthContext = build_auth_context([{identity, IdentityID}], [], Context),
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
            {ok, Destination = #{<<"id">> := DestinationId}} ->
                wapi_handler_utils:reply_ok(201, Destination, get_location('GetDestination', [DestinationId], Opts));
            {error, {identity, notfound}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"No such identity">>));
            {error, {currency, notfound}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"Currency not supported">>));
            {error, inaccessible} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"Identity inaccessible">>));
            {error, {external_id_conflict, {ID, ExternalID}}} ->
                wapi_handler_utils:logic_error(external_id_conflict, {ID, ExternalID});
            {error, {invalid_resource_token, Type}} ->
                wapi_handler_utils:reply_ok(400, #{
                    <<"errorType">> => <<"InvalidResourceToken">>,
                    <<"name">> => Type,
                    <<"description">> => <<"Specified resource token is invalid">>
                })
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare(
    OperationID = 'IssueDestinationGrant',
    #{
        'destinationID' := DestinationId,
        'DestinationGrantRequest' := #{<<"validUntil">> := Expiration}
    },
    Context,
    _Opts
) ->
    AuthContext = build_auth_context([{destination, DestinationId}], [], Context),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case issue_grant_token({destinations, DestinationId}, Expiration, Context) of
            {ok, Token} ->
                wapi_handler_utils:reply_ok(201, #{
                    <<"token">> => Token,
                    <<"validUntil">> => Expiration
                });
            {error, expired} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Invalid expiration: already expired">>)
                )
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
%% Withdrawals
prepare(OperationID = 'CreateQuote', Req = #{'WithdrawalQuoteParams' := Params}, Context, _Opts) ->
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
        case wapi_withdrawal_backend:create_quote(Req, Context) of
            {ok, Quote} ->
                wapi_handler_utils:reply_ok(202, Quote);
            {error, {destination, notfound}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"No such destination">>));
            {error, {destination, unauthorized}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"Destination unauthorized">>));
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
            {error, {identity_providers_mismatch, _}} ->
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
prepare(OperationID = 'CreateWithdrawal', #{'WithdrawalParameters' := Params}, Context, Opts) ->
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
            {ok, Withdrawal = #{<<"id">> := WithdrawalId}} ->
                wapi_handler_utils:reply_ok(202, Withdrawal, get_location('GetWithdrawal', [WithdrawalId], Opts));
            {error, {destination, notfound}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"No such destination">>));
            {error, {destination, unauthorized}} ->
                wapi_handler_utils:reply_ok(422, wapi_handler_utils:get_error_msg(<<"Destination unauthorized">>));
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
            {error, {identity_providers_mismatch, _}} ->
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
prepare(OperationID = 'GetWithdrawal', #{'withdrawalID' := WithdrawalId}, Context, _Opts) ->
    {ResultWithdrawal, ResultWithdrawalOwner} =
        case wapi_withdrawal_backend:get(WithdrawalId, Context) of
            {ok, Withdrawal, Owner} -> {Withdrawal, Owner};
            {error, {withdrawal, notfound}} -> {undefined, undefined}
        end,
    Authorize = fun() ->
        Prototypes = [
            {
                operation,
                #{withdrawal => WithdrawalId, id => OperationID}
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
prepare(OperationID = 'GetWithdrawalByExternalID', #{'externalID' := ExternalID}, Context, _Opts) ->
    {ResultWithdrawal, ResultWithdrawalOwner, WithdrawalId} =
        case wapi_withdrawal_backend:get_by_external_id(ExternalID, Context) of
            {ok, Wallet = #{<<"id">> := ID}, Owner} -> {Wallet, Owner, ID};
            {error, {withdrawal, notfound}} -> {undefined, undefined, undefined};
            {error, {external_id, {unknown_external_id, ExternalID}}} -> {undefined, undefined, undefined}
        end,
    Authorize = fun() ->
        Prototypes = [
            {
                operation,
                #{withdrawal => WithdrawalId, id => OperationID}
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
prepare(OperationID = 'ListWithdrawals', Req, Context, _Opts) ->
    AuthContext = build_auth_context(
        [
            wapi_handler_utils:maybe_with('identityID', Req, fun(IdentityID) -> {identity, IdentityID} end),
            wapi_handler_utils:maybe_with('walletID', Req, fun(WalletID) -> {wallet, WalletID} end),
            wapi_handler_utils:maybe_with('withdrawalID', Req, fun(WithdrawalID) -> {withdrawal, WithdrawalID} end),
            wapi_handler_utils:maybe_with('destinationID', Req, fun(DestinationID) -> {destination, DestinationID} end)
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
prepare(OperationID = 'PollWithdrawalEvents', Req = #{'withdrawalID' := WithdrawalId}, Context, _Opts) ->
    AuthContext = build_auth_context([{withdrawal, WithdrawalId}], [], Context),
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
    OperationID = 'GetWithdrawalEvents',
    #{
        'withdrawalID' := WithdrawalId,
        'eventID' := EventId
    },
    Context,
    _Opts
) ->
    AuthContext = build_auth_context([{withdrawal, WithdrawalId}], [], Context),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_withdrawal_backend:get_event(WithdrawalId, EventId, Context) of
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
prepare(OperationID = 'ListDeposits', Req, Context, _Opts) ->
    AuthContext = build_auth_context(
        [
            wapi_handler_utils:maybe_with('identityID', Req, fun(IdentityID) -> {identity, IdentityID} end),
            wapi_handler_utils:maybe_with('walletID', Req, fun(WalletID) -> {wallet, WalletID} end)
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
prepare(OperationID = 'ListDepositReverts', Req, Context, _Opts) ->
    AuthContext = build_auth_context(
        [
            wapi_handler_utils:maybe_with('identityID', Req, fun(IdentityID) -> {identity, IdentityID} end),
            wapi_handler_utils:maybe_with('walletID', Req, fun(WalletID) -> {wallet, WalletID} end)
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
        case wapi_stat_backend:list_deposit_reverts(Req, Context) of
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
prepare(OperationID = 'ListDepositAdjustments', Req, Context, _Opts) ->
    AuthContext = build_auth_context(
        [
            wapi_handler_utils:maybe_with('identityID', Req, fun(IdentityID) -> {identity, IdentityID} end),
            wapi_handler_utils:maybe_with('walletID', Req, fun(WalletID) -> {wallet, WalletID} end)
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
        case wapi_stat_backend:list_deposit_adjustments(Req, Context) of
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
%% W2W
prepare(
    OperationID = 'CreateW2WTransfer',
    #{'W2WTransferParameters' := Params = #{<<"sender">> := SenderID}},
    Context,
    _Opts
) ->
    AuthContext = build_auth_context([{wallet, SenderID}], [], Context),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_w2w_backend:create_transfer(Params, Context) of
            {ok, W2WTransfer} ->
                wapi_handler_utils:reply_ok(202, W2WTransfer);
            {error, {wallet_from, notfound}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"No such wallet sender">>)
                );
            {error, {wallet_from, inaccessible}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Wallet inaccessible">>)
                );
            {error, {wallet_to, notfound}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"No such wallet receiver">>)
                );
            {error, {wallet_to, inaccessible}} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Wallet inaccessible">>)
                );
            {error, not_allowed_currency} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Currency not allowed">>)
                );
            {error, bad_w2w_transfer_amount} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Bad transfer amount">>)
                );
            {error, inconsistent_currency} ->
                wapi_handler_utils:reply_ok(
                    422,
                    wapi_handler_utils:get_error_msg(<<"Inconsistent currency">>)
                )
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare(OperationID = 'GetW2WTransfer', #{w2wTransferID := W2WTransferId}, Context, _Opts) ->
    {ResultW2WTransfer, ResultW2WTransferOwner} =
        case wapi_w2w_backend:get_transfer(W2WTransferId, Context) of
            {ok, W2WTransfer, Owner} -> {W2WTransfer, Owner};
            {error, {w2w_transfer, {unknown_w2w_transfer, _ID}}} -> {undefined, undefined}
        end,
    Authorize = fun() ->
        Prototypes = [
            {
                operation,
                #{w2w_transfer => W2WTransferId, id => OperationID}
            },
            {wallet, [
                wapi_bouncer_context:build_wallet_entity(
                    w2w_transfer,
                    ResultW2WTransfer,
                    {party, ResultW2WTransferOwner}
                )
            ]}
        ],
        Resolution = mask_notfound(wapi_auth:authorize_operation(Prototypes, Context)),
        {ok, Resolution}
    end,
    Process = fun() ->
        wapi_handler_utils:reply_ok(200, ResultW2WTransfer)
    end,
    {ok, #{authorize => Authorize, process => Process}};
%% Webhooks
prepare(
    OperationID = 'CreateWebhook',
    Req = #{'Webhook' := #{<<"identityID">> := IdentityId, <<"scope">> := Scope}},
    Context,
    _Opts
) ->
    AuthContext = build_auth_context(
        [
            {identity, IdentityId},
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
        case wapi_webhook_backend:create_webhook(Req, Context) of
            {ok, Webhook} ->
                wapi_handler_utils:reply_ok(201, Webhook)
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare(OperationID = 'GetWebhooks', #{identityID := IdentityID}, Context, _Opts) ->
    AuthContext = build_auth_context([{identity, IdentityID}], [], Context),
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{id => OperationID}, AuthContext)},
            {wallet, build_prototype_for(wallet, [], AuthContext)}
        ],
        Resolution = wapi_auth:authorize_operation(Prototypes, Context),
        {ok, Resolution}
    end,
    Process = fun() ->
        case wapi_webhook_backend:get_webhooks(IdentityID, Context) of
            {ok, Webhooks} ->
                wapi_handler_utils:reply_ok(200, Webhooks)
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare(OperationID = 'GetWebhookByID', #{identityID := IdentityID, webhookID := WebhookID}, Context, _Opts) ->
    AuthContext = build_auth_context(
        [
            {identity, IdentityID},
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
    OperationID = 'DeleteWebhookByID',
    #{identityID := IdentityID, webhookID := WebhookID},
    Context,
    _Opts
) ->
    AuthContext = build_auth_context(
        [
            {identity, IdentityID},
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
prepare(OperationID = 'CreateReport', Req = #{identityID := IdentityID}, Context, _Opts) ->
    AuthContext = build_auth_context([{identity, IdentityID}], [], Context),
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
            {error, {identity, notfound}} ->
                wapi_handler_utils:reply_ok(400, #{
                    <<"errorType">> => <<"NotFound">>,
                    <<"name">> => <<"identity">>,
                    <<"description">> => <<"identity not found">>
                });
            {error, invalid_request} ->
                wapi_handler_utils:reply_ok(400, #{
                    <<"errorType">> => <<"NoMatch">>,
                    <<"name">> => <<"timestamps">>,
                    <<"description">> => <<"invalid time range">>
                });
            {error, invalid_contract} ->
                wapi_handler_utils:reply_ok(400, #{
                    <<"errorType">> => <<"NotFound">>,
                    <<"name">> => <<"contractID">>,
                    <<"description">> => <<"contract not found">>
                })
        end
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare(
    OperationID = 'GetReport',
    #{
        identityID := IdentityID,
        reportID := ReportId
    },
    Context,
    _Opts
) ->
    AuthContext = build_auth_context([{identity, IdentityID}], [], Context),
    ResultReport =
        case wapi_report_backend:get_report(ReportId, IdentityID, Context) of
            {ok, Report} ->
                Report;
            {error, {identity, notfound}} ->
                undefined;
            {error, notfound} ->
                undefined
        end,
    Authorize = fun() ->
        Prototypes = [
            {operation, build_prototype_for(operation, #{report => ReportId, id => OperationID}, AuthContext)},
            {wallet,
                build_prototype_for(
                    wallet,
                    [wapi_bouncer_context:build_wallet_entity(report, ResultReport, {identity, IdentityID})],
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
prepare(OperationID = 'GetReports', Req = #{identityID := IdentityID}, Context, _Opts) ->
    AuthContext = build_auth_context([{identity, IdentityID}], [], Context),
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
            {error, {identity, notfound}} ->
                wapi_handler_utils:reply_ok(400, #{
                    <<"errorType">> => <<"NotFound">>,
                    <<"name">> => <<"identity">>,
                    <<"description">> => <<"identity not found">>
                });
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
prepare(OperationID = 'DownloadFile', #{fileID := FileId}, Context, _Opts) ->
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
prepare(OperationID = 'GetResidence', #{'residence' := ResidenceId}, Context, _Opts) ->
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
prepare(OperationID = 'GetCurrency', #{'currencyID' := CurrencyId}, Context, _Opts) ->
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
get_location(OperationId, Params, Opts) ->
    #{path := PathSpec} = swag_server_wallet_router:get_operation(OperationId),
    wapi_handler_utils:get_location(PathSpec, Params, Opts).

issue_grant_token(TokenSpec, Expiration, Context) ->
    case get_expiration_deadline(Expiration) of
        {ok, Deadline} ->
            {ok, wapi_tokens_legacy:issue_access_token(wapi_handler_utils:get_owner(Context), TokenSpec, Deadline)};
        Error = {error, _} ->
            Error
    end.

get_expiration_deadline(Expiration) ->
    {DateTime, MilliSec} = woody_deadline:from_binary(wapi_utils:to_universal_time(Expiration)),
    Deadline = genlib_time:daytime_to_unixtime(DateTime) + MilliSec div 1000,
    case genlib_time:unow() - Deadline < 0 of
        true ->
            {ok, Deadline};
        false ->
            {error, expired}
    end.

build_auth_context([], Acc, _Context) ->
    Acc;
build_auth_context([undefined | T], Acc, Context) ->
    build_auth_context(T, Acc, Context);
build_auth_context([H | T], Acc, Context) ->
    AuthContext = build_auth_context(H, Context),
    build_auth_context(T, [AuthContext | Acc], Context).

build_auth_context({identity, IdentityID}, Context) ->
    {ResultIdentity, ResultIdentityOwner} =
        case wapi_identity_backend:get_identity(IdentityID, Context) of
            {ok, Identity, Owner} -> {Identity, Owner};
            {error, {identity, notfound}} -> {undefined, undefined}
        end,
    {identity, {IdentityID, ResultIdentity, ResultIdentityOwner}};
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
build_auth_context({withdrawal, WithdrawalId}, Context) ->
    {ResultWithdrawal, ResultWithdrawalOwner} =
        case wapi_withdrawal_backend:get(WithdrawalId, Context) of
            {ok, Withdrawal, Owner} -> {Withdrawal, Owner};
            {error, {withdrawal, notfound}} -> {undefined, undefined}
        end,
    {withdrawal, {WithdrawalId, ResultWithdrawal, ResultWithdrawalOwner}};
build_auth_context({webhook, WebhookId}, Context) ->
    ResultWebhook =
        case wapi_webhook_backend:get_webhook(WebhookId, Context) of
            {ok, Webhook} -> Webhook;
            {error, notfound} -> undefined
        end,
    {webhook, {WebhookId, ResultWebhook}}.

build_prototype_for(operation, OpContext, AuthContext) ->
    lists:foldl(
        fun
            ({identity, {IdentityID, _Identity, _Owner}}, Acc) ->
                Acc#{identity => IdentityID};
            ({wallet, {WalletID, _Wallet, _Owner}}, Acc) ->
                Acc#{wallet => WalletID};
            ({destination, {DestinationID, _Destination, _Owner}}, Acc) ->
                Acc#{destination => DestinationID};
            ({withdrawal, {WithdrawalID, _Withdrawal, _Owner}}, Acc) ->
                Acc#{withdrawal => WithdrawalID};
            ({webhook, {WebhookId, _ResultWebhook}}, Acc) ->
                Acc#{webhook => WebhookId}
        end,
        OpContext,
        AuthContext
    );
build_prototype_for(wallet, Entities, AuthContext) ->
    lists:foldl(
        fun
            ({identity, {_IdentityID, Identity, Owner}}, Acc) ->
                [wapi_bouncer_context:build_wallet_entity(identity, Identity, {party, Owner}) | Acc];
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

% seconds
-define(DEFAULT_URL_LIFETIME, 60).

get_default_url_lifetime() ->
    Now = erlang:system_time(second),
    Lifetime = application:get_env(wapi, file_storage_url_lifetime, ?DEFAULT_URL_LIFETIME),
    genlib_rfc3339:format(Now + Lifetime, second).

maybe_to_list(undefined) ->
    [];
maybe_to_list(T) ->
    [T].
