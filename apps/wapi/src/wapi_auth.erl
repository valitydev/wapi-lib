-module(wapi_auth).

-export([get_subject_id/1]).
-export([get_subject_email/1]).
-export([get_subject_name/1]).

-export([preauthorize_api_key/1]).
-export([authorize_api_key/3]).
-export([authorize_operation/3]).
-export([issue_access_token/2]).
-export([issue_access_token/3]).

-export([get_resource_hierarchy/0]).

-export([get_verification_options/0]).

-export([get_access_config/0]).

-export([get_signee/0]).

-export([create_wapi_context/1]).
-export([extract_legacy_auth_context/1]).

-type context() :: uac_authorizer_jwt:t().
-type claims() :: uac_authorizer_jwt:claims().
-type consumer() :: client | merchant | provider.

-export_type([context/0]).
-export_type([claims/0]).
-export_type([consumer/0]).
-export_type([metadata/0]).
-export_type([resolution/0]).
-export_type([preauth_context/0]).
-export_type([auth_context/0]).

%%

-type auth_method() :: bearer_token | grant.
-type token_type() :: bearer.

-type auth_context() ::
    {authorized, #{
        legacy := uac:context(),
        auth_data => token_keeper_auth_data:auth_data()
    }}.
-type preauth_context() :: {unauthorized, {token_type(), token_keeper_client:token()}}.

-type resource() :: wallet | destination.
-type auth_details() :: auth_method() | [{resource(), auth_details()}].
-type realm() :: binary().
-type resolution() ::
    allowed
    | forbidden
    | {forbidden, _Reason}.

-type metadata() :: #{
    auth_method => auth_method(),
    user_realm => realm()
}.

-define(DOMAIN, <<"wallet-api">>).
-define(authorized(Ctx), {authorized, Ctx}).
-define(unauthorized(Ctx), {unauthorized, Ctx}).

-spec get_subject_id(auth_context()) -> binary() | undefined.
get_subject_id(?authorized(#{auth_data := AuthData})) ->
    case get_party_id(AuthData) of
        PartyId when is_binary(PartyId) ->
            PartyId;
        undefined ->
            get_user_id(AuthData)
    end;
get_subject_id(?authorized(#{legacy := Context})) ->
    uac_authorizer_jwt:get_subject_id(Context).

-spec get_subject_email(auth_context()) -> binary() | undefined.
get_subject_email(?authorized(#{auth_data := AuthData})) ->
    get_user_email(AuthData);
get_subject_email(?authorized(#{legacy := Context})) ->
    uac_authorizer_jwt:get_claim(<<"email">>, Context, undefined).

-spec get_subject_name(auth_context()) -> binary() | undefined.
get_subject_name(?authorized(#{auth_data := _AuthData})) ->
    %% Subject names are no longer a thing for auth_data contexts
    undefined;
get_subject_name(?authorized(#{legacy := Context})) ->
    uac_authorizer_jwt:get_claim(<<"name">>, Context, undefined).

get_party_id(AuthData) ->
    get_metadata(get_metadata_mapped_key(party_id), token_keeper_auth_data:get_metadata(AuthData)).

get_user_id(AuthData) ->
    get_metadata(get_metadata_mapped_key(user_id), token_keeper_auth_data:get_metadata(AuthData)).

get_user_email(AuthData) ->
    get_metadata(get_metadata_mapped_key(user_email), token_keeper_auth_data:get_metadata(AuthData)).

get_metadata(Key, Metadata) ->
    maps:get(Key, Metadata, undefined).

get_metadata_mapped_key(Key) ->
    maps:get(Key, get_meta_mappings()).

get_meta_mappings() ->
    AuthConfig = genlib_app:env(wapi, auth_config),
    maps:get(metadata_mappings, AuthConfig).

%

-spec preauthorize_api_key(swag_server_wallet:api_key()) -> {ok, preauth_context()} | {error, _Reason}.
preauthorize_api_key(ApiKey) ->
    case parse_api_key(ApiKey) of
        {ok, Token} ->
            {ok, ?unauthorized(Token)};
        {error, Error} ->
            {error, Error}
    end.

-spec authorize_api_key(preauth_context(), token_keeper_client:source_context(), woody_context:ctx()) ->
    {ok, auth_context()} | {error, _Reason}.
authorize_api_key(?unauthorized({TokenType, Token}), TokenContext, WoodyContext) ->
    authorize_token_by_type(TokenType, Token, TokenContext, WoodyContext).

authorize_token_by_type(bearer = TokenType, Token, TokenContext, WoodyContext) ->
    %% NONE: For now legacy auth still takes precedence over
    %% bouncer-based auth, so we MUST have a legacy context
    case uac:authorize_api_key(restore_api_key(TokenType, Token), #{}) of
        {ok, LegacyContext} ->
            case token_keeper_client:get_by_token(Token, TokenContext, WoodyContext) of
                {ok, AuthData} ->
                    {ok, {authorized, make_context(AuthData, LegacyContext)}};
                {error, TokenKeeperError} ->
                    _ = logger:warning("Token keeper authorization failed: ~p", [TokenKeeperError]),
                    {error, {auth_failed, TokenKeeperError}}
            end;
        {error, LegacyError} ->
            {error, {legacy_auth_failed, LegacyError}}
    end.

-spec authorize_operation(
    Prototypes :: wapi_bouncer_context:prototypes(),
    Context :: wapi_handler:context(),
    Req :: wapi_handler:req_data()
) -> resolution().
authorize_operation(
    Prototypes,
    Context = #{operation_id := OperationID},
    Req
) ->
    OperationACL = get_operation_access(OperationID, Req),
    OldAuthResult = uac:authorize_operation(OperationACL, create_wapi_context(extract_legacy_auth_context(Context))),
    AuthResult = do_authorize_operation(Prototypes, Context),
    map_old_auth_result(handle_auth_result(OldAuthResult, AuthResult)).

-type token_spec() ::
    {p2p_templates, P2PTemplateID :: binary(), Data :: map()}
    | {p2p_template_transfers, P2PTemplateID :: binary(), Data :: map()}
    | {destinations, DestinationID :: binary()}
    | {wallets, WalletID :: binary(), Asset :: map()}.

-spec issue_access_token(wapi_handler_utils:owner(), token_spec()) -> uac_authorizer_jwt:token().
issue_access_token(PartyID, TokenSpec) ->
    issue_access_token(PartyID, TokenSpec, unlimited).

-spec issue_access_token(wapi_handler_utils:owner(), token_spec(), uac_authorizer_jwt:expiration()) ->
    uac_authorizer_jwt:token().
issue_access_token(PartyID, TokenSpec, Expiration) ->
    Claims0 = resolve_token_spec(TokenSpec),
    Claims = Claims0#{<<"exp">> => Expiration},
    wapi_utils:unwrap(
        uac_authorizer_jwt:issue(
            wapi_utils:get_unique_id(),
            PartyID,
            Claims,
            get_signee()
        )
    ).

-spec resolve_token_spec(token_spec()) -> claims().
resolve_token_spec({p2p_templates, P2PTemplateID, #{<<"expiration">> := Expiration}}) ->
    #{
        <<"data">> => #{<<"expiration">> => Expiration},
        <<"resource_access">> => #{
            ?DOMAIN => uac_acl:from_list(
                [
                    {[{p2p_templates, P2PTemplateID}, p2p_template_tickets], write},
                    {[{p2p_templates, P2PTemplateID}], read}
                ]
            )
        }
    };
resolve_token_spec({p2p_template_transfers, P2PTemplateID, #{<<"transferID">> := TransferID}}) ->
    #{
        <<"data">> => #{<<"transferID">> => TransferID},
        <<"resource_access">> => #{
            ?DOMAIN => uac_acl:from_list(
                [
                    {[{p2p_templates, P2PTemplateID}, p2p_template_transfers], write},
                    {[{p2p_templates, P2PTemplateID}, p2p_template_quotes], write},
                    {[{p2p, TransferID}], read}
                ]
            )
        }
    };
resolve_token_spec({destinations, DestinationId}) ->
    #{
        <<"resource_access">> => #{
            ?DOMAIN => uac_acl:from_list(
                [{[party, {destinations, DestinationId}], write}]
            )
        }
    };
resolve_token_spec({wallets, WalletId, #{<<"amount">> := Amount, <<"currency">> := Currency}}) ->
    #{
        <<"amount">> => Amount,
        <<"currency">> => Currency,
        <<"resource_access">> => #{
            ?DOMAIN => uac_acl:from_list(
                [{[party, {wallets, WalletId}], write}]
            )
        }
    }.

%%

get_operation_access('GetCurrency', _) ->
    [{[party], read}];
get_operation_access('ListDeposits', _) ->
    [{[party], read}];
get_operation_access('ListDepositReverts', _) ->
    [{[party], read}];
get_operation_access('ListDepositAdjustments', _) ->
    [{[party], read}];
get_operation_access('ListDestinations', _) ->
    [{[party, destinations], read}];
get_operation_access('CreateDestination', _) ->
    [{[party, destinations], write}];
get_operation_access('GetDestination', #{destinationID := ID}) ->
    [{[party, {destinations, ID}], read}];
get_operation_access('GetDestinationByExternalID', _) ->
    [{[party, destinations], read}];
get_operation_access('IssueDestinationGrant', #{destinationID := ID}) ->
    [{[party, {destinations, ID}], write}];
get_operation_access('DownloadFile', _) ->
    [{[party], write}];
get_operation_access('ListIdentities', _) ->
    [{[party], read}];
get_operation_access('CreateIdentity', _) ->
    [{[party], write}];
get_operation_access('GetIdentity', _) ->
    [{[party], read}];
get_operation_access('ListIdentityChallenges', _) ->
    [{[party], read}];
get_operation_access('StartIdentityChallenge', _) ->
    [{[party], write}];
get_operation_access('GetIdentityChallenge', _) ->
    [{[party], read}];
get_operation_access('PollIdentityChallengeEvents', _) ->
    [{[party], read}];
get_operation_access('GetIdentityChallengeEvent', _) ->
    [{[party], read}];
get_operation_access('CreateReport', _) ->
    [{[party], write}];
get_operation_access('GetReports', _) ->
    [{[party], read}];
get_operation_access('GetReport', _) ->
    [{[party], read}];
get_operation_access('ListProviders', _) ->
    [{[party], read}];
get_operation_access('GetProvider', _) ->
    [{[party], read}];
get_operation_access('ListProviderIdentityClasses', _) ->
    [{[party], read}];
get_operation_access('GetProviderIdentityClass', _) ->
    [{[party], read}];
get_operation_access('ListProviderIdentityLevels', _) ->
    [{[party], read}];
get_operation_access('GetProviderIdentityLevel', _) ->
    [{[party], read}];
get_operation_access('GetResidence', _) ->
    [{[party], read}];
get_operation_access('ListWallets', _) ->
    [{[party, wallets], read}];
get_operation_access('CreateWallet', _) ->
    [{[party, wallets], write}];
get_operation_access('GetWallet', #{walletID := ID}) ->
    [{[party, {wallets, ID}], read}];
get_operation_access('GetWalletByExternalID', _) ->
    [{[party], read}];
get_operation_access('GetWalletAccount', #{walletID := ID}) ->
    [{[party, {wallets, ID}], read}];
get_operation_access('IssueWalletGrant', #{walletID := ID}) ->
    [{[party, {wallets, ID}], write}];
get_operation_access('CreateWebhook', _) ->
    [{[webhooks], write}];
get_operation_access('GetWebhooks', _) ->
    [{[webhooks], read}];
get_operation_access('GetWebhookByID', _) ->
    [{[webhooks], read}];
get_operation_access('DeleteWebhookByID', _) ->
    [{[webhooks], write}];
get_operation_access('CreateQuote', _) ->
    [{[withdrawals, withdrawal_quotes], write}];
get_operation_access('ListWithdrawals', _) ->
    [{[withdrawals], read}];
get_operation_access('CreateWithdrawal', _) ->
    [{[withdrawals], write}];
get_operation_access('GetWithdrawal', _) ->
    [{[withdrawals], read}];
get_operation_access('GetWithdrawalByExternalID', _) ->
    [{[withdrawals], read}];
get_operation_access('PollWithdrawalEvents', _) ->
    [{[withdrawals], read}];
get_operation_access('GetWithdrawalEvents', _) ->
    [{[withdrawals], read}];
get_operation_access('CreateP2PTransfer', _) ->
    [{[p2p], write}];
get_operation_access('QuoteP2PTransfer', _) ->
    [{[p2p, p2p_quotes], write}];
get_operation_access('GetP2PTransfer', #{'p2pTransferID' := ID}) ->
    [{[{p2p, ID}], read}];
get_operation_access('GetP2PTransferEvents', _) ->
    [{[p2p], read}];
get_operation_access('CreateP2PTransferTemplate', _) ->
    [{[p2p_templates], write}];
get_operation_access('GetP2PTransferTemplateByID', #{'p2pTransferTemplateID' := ID}) ->
    [{[{p2p_templates, ID}], read}];
get_operation_access('BlockP2PTransferTemplate', _) ->
    [{[p2p_templates], write}];
get_operation_access('IssueP2PTransferTemplateAccessToken', _) ->
    [{[p2p_templates], write}];
get_operation_access('IssueP2PTransferTicket', #{'p2pTransferTemplateID' := ID}) ->
    [{[{p2p_templates, ID}, p2p_template_tickets], write}];
get_operation_access('CreateP2PTransferWithTemplate', #{'p2pTransferTemplateID' := ID}) ->
    [{[{p2p_templates, ID}, p2p_template_transfers], write}];
get_operation_access('QuoteP2PTransferWithTemplate', #{'p2pTransferTemplateID' := ID}) ->
    [{[{p2p_templates, ID}, p2p_template_quotes], write}];
get_operation_access('CreateW2WTransfer', _) ->
    [{[w2w], write}];
get_operation_access('GetW2WTransfer', _) ->
    [{[w2w], read}].

-spec get_access_config() -> map().
get_access_config() ->
    #{
        domain_name => ?DOMAIN,
        resource_hierarchy => get_resource_hierarchy()
    }.

-spec get_resource_hierarchy() -> #{atom() => map()}.
%% TODO put some sense in here
% This resource hierarchy refers to wallet api actaully
get_resource_hierarchy() ->
    #{
        party => #{
            wallets => #{},
            destinations => #{}
        },
        p2p => #{p2p_quotes => #{}},
        p2p_templates => #{
            p2p_template_tickets => #{},
            p2p_template_transfers => #{},
            p2p_template_quotes => #{}
        },
        w2w => #{},
        webhooks => #{},
        withdrawals => #{withdrawal_quotes => #{}}
    }.

-spec get_verification_options() -> uac:verification_opts().
get_verification_options() ->
    #{}.

all_scopes(Key, Value, AccIn) ->
    Scopes0 = maps:fold(fun all_scopes/3, [], Value),
    Scopes1 = lists:map(fun(Scope) -> [Key | Scope] end, Scopes0),
    Scopes1 ++ [[Key] | AccIn].

hierarchy_to_acl(Hierarchy) ->
    Scopes = maps:fold(fun all_scopes/3, [], Hierarchy),
    lists:foldl(
        fun(Scope, ACL0) ->
            uac_acl:insert_scope(Scope, write, uac_acl:insert_scope(Scope, read, ACL0))
        end,
        uac_acl:new(),
        Scopes
    ).

-spec create_wapi_context(uac_authorizer_jwt:t()) -> uac_authorizer_jwt:t().
create_wapi_context({ID, Party, Claims, Metadata}) ->
    % Create new acl
    % So far we want to give every token full set of permissions
    % This is a temporary solution
    % @TODO remove when we issue new tokens
    NewClaims = maybe_grant_wapi_roles(Claims),
    {ID, Party, NewClaims, Metadata}.

maybe_grant_wapi_roles(Claims) ->
    case genlib_map:get(<<"resource_access">>, Claims) of
        #{?DOMAIN := _} ->
            Claims;
        #{<<"common-api">> := _} ->
            Hierarchy = wapi_auth:get_resource_hierarchy(),
            Claims#{
                <<"resource_access">> => #{?DOMAIN => #{<<"roles">> => uac_acl:encode(hierarchy_to_acl(Hierarchy))}}
            };
        _ ->
            undefined
    end.

-spec get_signee() -> term().
get_signee() ->
    wapi_utils:unwrap(application:get_env(wapi, signee)).

handle_auth_result(ok, allowed) ->
    ok;
handle_auth_result(Res = {error, unauthorized}, forbidden) ->
    Res;
handle_auth_result(Res, undefined) ->
    Res;
handle_auth_result(OldRes, NewRes) ->
    _ = logger:warning("New auth ~p differ from old ~p", [NewRes, OldRes]),
    OldRes.

map_old_auth_result(ok) -> allowed;
map_old_auth_result({error, unauthorized}) -> forbidden.

extract_auth_context(#{swagger_context := #{auth_context := ?authorized(AuthContext)}}) ->
    AuthContext.

-spec extract_legacy_auth_context(wapi_handler:context()) -> uac:context().
extract_legacy_auth_context(#{swagger_context := #{auth_context := ?authorized(AuthContext)}}) ->
    maps:get(legacy, AuthContext).

get_auth_data(AuthContext) ->
    maps:get(auth_data, AuthContext).

%% TODO: Remove this clause after all handlers will be implemented
do_authorize_operation([], _) ->
    undefined;
do_authorize_operation(Prototypes, Context = #{swagger_context := SwagContext, woody_context := WoodyContext}) ->
    AuthData = get_auth_data(extract_auth_context(Context)),
    Fragments = wapi_bouncer:gather_context_fragments(
        token_keeper_auth_data:get_context_fragment(AuthData),
        get_user_id(AuthData),
        SwagContext,
        WoodyContext
    ),
    Fragments1 = wapi_bouncer_context:build(Prototypes, Fragments),
    try
        wapi_bouncer:judge(Fragments1, WoodyContext)
    catch
        error:{woody_error, _Error} ->
            % TODO
            % This is temporary safeguard around bouncer integration put here so that
            % external requests would remain undisturbed by bouncer intermittent failures.
            % We need to remove it as soon as these two points come true:
            % * bouncer proves to be stable enough,
            % * capi starts depending on bouncer exclusively for authz decisions.
            undefined
    end.

parse_api_key(<<"Bearer ", Token/binary>>) ->
    {ok, {bearer, Token}};
parse_api_key(_) ->
    {error, unsupported_auth_scheme}.

restore_api_key(bearer, Token) ->
    %% Kind of a hack since legacy auth expects the full api key string, but
    %% token-keeper does not and we got rid of it at preauth stage
    <<"Bearer ", Token/binary>>.

make_context(AuthData, LegacyContext) ->
    genlib_map:compact(#{
        legacy => LegacyContext,
        auth_data => AuthData
    }).
