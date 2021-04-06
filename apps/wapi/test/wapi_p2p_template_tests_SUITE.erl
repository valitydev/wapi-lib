-module(wapi_p2p_template_tests_SUITE).

-behaviour(supervisor).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("wapi_wallet_dummy_data.hrl").
-include_lib("fistful_proto/include/ff_proto_p2p_template_thrift.hrl").
-include_lib("fistful_proto/include/ff_proto_p2p_transfer_thrift.hrl").

-export([init/1]).

-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([create_ok_test/1]).
-export([get_ok_test/1]).
-export([block_ok_test/1]).
-export([issue_access_token_ok_test/1]).
-export([issue_transfer_ticket_ok_test/1]).
-export([issue_transfer_ticket_with_access_expiration_ok_test/1]).
-export([quote_transfer_ok_test/1]).
-export([quote_transfer_fail_resource_token_invalid_test/1]).
-export([quote_transfer_fail_resource_token_expire_test/1]).
-export([create_transfer_ok_test/1]).
-export([create_transfer_fail_resource_token_invalid_test/1]).
-export([create_transfer_fail_resource_token_expire_test/1]).

% common-api is used since it is the domain used in production RN
% TODO: change to wallet-api (or just omit since it is the default one) when new tokens will be a thing
-define(DOMAIN, <<"common-api">>).
-define(badresp(Code), {error, {invalid_response_code, Code}}).
-define(emptyresp(Code), {error, {Code, #{}}}).

-type test_case_name() :: atom().
-type config() :: [{atom(), any()}].
-type group_name() :: atom().

%% Behaviour

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    {ok, {#{strategy => one_for_all, intensity => 1, period => 1}, []}}.

%% Configure tests

-spec all() -> [{group, test_case_name()}].
all() ->
    [
        {group, base}
    ].

-spec groups() -> [{group_name(), list(), [test_case_name()]}].
groups() ->
    [
        {base, [], [
            create_ok_test,
            get_ok_test,
            block_ok_test,
            issue_access_token_ok_test,
            issue_transfer_ticket_ok_test,
            issue_transfer_ticket_with_access_expiration_ok_test,
            quote_transfer_ok_test,
            quote_transfer_fail_resource_token_invalid_test,
            quote_transfer_fail_resource_token_expire_test,
            create_transfer_ok_test,
            create_transfer_fail_resource_token_invalid_test,
            create_transfer_fail_resource_token_expire_test
        ]}
    ].

-spec init_per_suite(config()) -> config().
init_per_suite(C) ->
    wapi_ct_helper:init_suite(?MODULE, C).

-spec end_per_suite(config()) -> _.
end_per_suite(C) ->
    _ = wapi_ct_helper:stop_mocked_service_sup(?config(suite_test_sup, C)),
    _ = [application:stop(App) || App <- ?config(apps, C)],
    ok.

-spec init_per_group(group_name(), config()) -> config().
init_per_group(Group, Config) when Group =:= base ->
    ok = wapi_context:save(
        wapi_context:create(#{
            woody_context => woody_context:new(<<"init_per_group/", (atom_to_binary(Group, utf8))/binary>>)
        })
    ),
    Party = genlib:bsuuid(),
    {ok, Token} = wapi_ct_helper:issue_token(Party, [{[party], write}], unlimited, ?DOMAIN),
    ContextPcidss = wapi_client_lib:get_context("wapi-pcidss:8080", Token, 10000, ipv4),
    Config1 = [{party, Party} | Config],
    [
        {context, wapi_ct_helper:get_context(Token)},
        {context_pcidss, ContextPcidss}
        | Config1
    ];
init_per_group(_, Config) ->
    Config.

-spec end_per_group(group_name(), config()) -> _.
end_per_group(_Group, _C) ->
    ok.

-spec init_per_testcase(test_case_name(), config()) -> config().
init_per_testcase(Name, C) ->
    C1 = wapi_ct_helper:makeup_cfg([wapi_ct_helper:test_case_name(Name), wapi_ct_helper:woody_ctx()], C),
    ok = wapi_context:save(C1),
    [{test_sup, wapi_ct_helper:start_mocked_service_sup(?MODULE)} | C1].

-spec end_per_testcase(test_case_name(), config()) -> _.
end_per_testcase(_Name, C) ->
    ok = wapi_context:cleanup(),
    _ = wapi_ct_helper:stop_mocked_service_sup(?config(test_sup, C)),
    ok.

%% Tests

-spec create_ok_test(config()) -> _.
create_ok_test(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper:mock_services(
        [
            {bender_thrift, fun('GenerateID', _) -> {ok, ?GENERATE_ID_RESULT} end},
            {fistful_identity, fun('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)} end},
            {fistful_p2p_template, fun('Create', _) -> {ok, ?P2P_TEMPLATE(PartyID)} end}
        ],
        C
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_p2_p_templates_api:create_p2_p_transfer_template/3,
        #{
            body => #{
                <<"identityID">> => ?STRING,
                <<"details">> => #{
                    <<"body">> => #{
                        <<"value">> => #{
                            <<"currency">> => ?RUB,
                            <<"amount">> => ?INTEGER
                        }
                    },
                    <<"metadata">> => #{
                        <<"defaultMetadata">> => #{
                            <<"some key">> => <<"some value">>
                        }
                    }
                }
            }
        },
        ?config(context, C)
    ).

-spec get_ok_test(config()) -> _.
get_ok_test(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_p2p_template, fun('Get', _) -> {ok, ?P2P_TEMPLATE(PartyID)} end}
        ],
        C
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_p2_p_templates_api:get_p2_p_transfer_template_by_id/3,
        #{
            binding => #{
                <<"p2pTransferTemplateID">> => ?STRING
            }
        },
        ?config(context, C)
    ).

-spec block_ok_test(config()) -> _.
block_ok_test(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_p2p_template, fun('Get', _) -> {ok, ?P2P_TEMPLATE(PartyID)} end}
        ],
        C
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_p2_p_templates_api:block_p2_p_transfer_template/3,
        #{
            binding => #{
                <<"p2pTransferTemplateID">> => ?STRING
            }
        },
        ?config(context, C)
    ).

-spec issue_access_token_ok_test(config()) -> _.
issue_access_token_ok_test(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_p2p_template, fun
                ('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)};
                ('Get', _) -> {ok, ?P2P_TEMPLATE(PartyID)}
            end}
        ],
        C
    ),
    ValidUntil = woody_deadline:to_binary(woody_deadline:from_timeout(100000)),
    {ok, #{<<"token">> := _Token}} = call_api(
        fun swag_client_wallet_p2_p_templates_api:issue_p2_p_transfer_template_access_token/3,
        #{
            binding => #{
                <<"p2pTransferTemplateID">> => ?STRING
            },
            body => #{
                <<"validUntil">> => ValidUntil
            }
        },
        ?config(context, C)
    ).

-spec issue_transfer_ticket_ok_test(config()) -> _.
issue_transfer_ticket_ok_test(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper:mock_services(
        [
            {bender_thrift, fun('GenerateID', _) -> {ok, ?GENERATE_ID_RESULT} end},
            {fistful_p2p_template, fun
                ('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)};
                ('Get', _) -> {ok, ?P2P_TEMPLATE(PartyID)}
            end}
        ],
        C
    ),
    ValidUntil = woody_deadline:to_binary(woody_deadline:from_timeout(100000)),
    TemplateToken = create_template_token(PartyID, ValidUntil),
    {ok, #{<<"token">> := _Token}} = call_api(
        fun swag_client_wallet_p2_p_templates_api:issue_p2_p_transfer_ticket/3,
        #{
            binding => #{
                <<"p2pTransferTemplateID">> => ?STRING
            },
            body => #{
                <<"validUntil">> => ValidUntil
            }
        },
        wapi_ct_helper:get_context(TemplateToken)
    ).

-spec issue_transfer_ticket_with_access_expiration_ok_test(config()) -> _.
issue_transfer_ticket_with_access_expiration_ok_test(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper:mock_services(
        [
            {bender_thrift, fun('GenerateID', _) -> {ok, ?GENERATE_ID_RESULT} end},
            {fistful_p2p_template, fun
                ('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)};
                ('Get', _) -> {ok, ?P2P_TEMPLATE(PartyID)}
            end}
        ],
        C
    ),
    AccessValidUntil = woody_deadline:to_binary(woody_deadline:from_timeout(100000)),
    TemplateToken = create_template_token(PartyID, AccessValidUntil),
    ValidUntil = woody_deadline:to_binary(woody_deadline:from_timeout(200000)),
    {ok, #{<<"token">> := _Token, <<"validUntil">> := AccessValidUntil}} = call_api(
        fun swag_client_wallet_p2_p_templates_api:issue_p2_p_transfer_ticket/3,
        #{
            binding => #{
                <<"p2pTransferTemplateID">> => ?STRING
            },
            body => #{
                <<"validUntil">> => ValidUntil
            }
        },
        wapi_ct_helper:get_context(TemplateToken)
    ).

-spec quote_transfer_ok_test(config()) -> _.
quote_transfer_ok_test(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_identity, fun('Get', _) -> {ok, ?IDENTITY(PartyID)} end},
            {fistful_p2p_template, fun
                ('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)};
                ('GetQuote', _) -> {ok, ?P2P_TEMPLATE_QUOTE}
            end}
        ],
        C
    ),
    ?assertMatch({ok, #{<<"token">> := _QuoteToken}}, quote_p2p_transfer_with_template_call_api(C)).

-spec quote_transfer_fail_resource_token_invalid_test(config()) -> _.
quote_transfer_fail_resource_token_invalid_test(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_p2p_template, fun('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)} end}
        ],
        C
    ),
    InvalidResourceToken = <<"v1.InvalidResourceToken">>,
    ValidResourceToken = create_card_token(),
    ?assertMatch(
        {error,
            {400, #{
                <<"errorType">> := <<"InvalidResourceToken">>,
                <<"name">> := <<"BankCardSenderResource">>
            }}},
        quote_p2p_transfer_with_template_call_api(C, InvalidResourceToken, ValidResourceToken)
    ),
    ?assertMatch(
        {error,
            {400, #{
                <<"errorType">> := <<"InvalidResourceToken">>,
                <<"name">> := <<"BankCardReceiverResource">>
            }}},
        quote_p2p_transfer_with_template_call_api(C, ValidResourceToken, InvalidResourceToken)
    ).

-spec quote_transfer_fail_resource_token_expire_test(config()) -> _.
quote_transfer_fail_resource_token_expire_test(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_p2p_template, fun('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)} end}
        ],
        C
    ),
    InvalidResourceToken = create_card_token(wapi_utils:deadline_from_timeout(0)),
    ValidResourceToken = create_card_token(),
    ?assertMatch(
        {error,
            {400, #{
                <<"errorType">> := <<"InvalidResourceToken">>,
                <<"name">> := <<"BankCardSenderResource">>
            }}},
        quote_p2p_transfer_with_template_call_api(C, InvalidResourceToken, ValidResourceToken)
    ),
    ?assertMatch(
        {error,
            {400, #{
                <<"errorType">> := <<"InvalidResourceToken">>,
                <<"name">> := <<"BankCardReceiverResource">>
            }}},
        quote_p2p_transfer_with_template_call_api(C, ValidResourceToken, InvalidResourceToken)
    ).

-spec create_transfer_ok_test(config()) -> _.
create_transfer_ok_test(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper:mock_services(
        [
            {bender_thrift, fun('GenerateID', _) -> {ok, ?GENERATE_ID_RESULT} end},
            {fistful_p2p_template, fun
                ('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)};
                ('Get', _) -> {ok, ?P2P_TEMPLATE(PartyID)};
                ('CreateTransfer', _) -> {ok, ?P2P_TEMPLATE_TRANSFER(PartyID)}
            end}
        ],
        C
    ),
    ValidUntil = woody_deadline:to_binary(woody_deadline:from_timeout(100000)),
    TemplateToken = create_template_token(PartyID, ValidUntil),
    Ticket = create_transfer_ticket(TemplateToken),
    ?assertMatch({ok, #{<<"id">> := ?STRING}}, create_p2p_transfer_with_template_call_api(C, Ticket)).

-spec create_transfer_fail_resource_token_invalid_test(config()) -> _.
create_transfer_fail_resource_token_invalid_test(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper:mock_services(
        [
            {bender_thrift, fun('GenerateID', _) -> {ok, ?GENERATE_ID_RESULT} end},
            {fistful_p2p_template, fun
                ('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)};
                ('Get', _) -> {ok, ?P2P_TEMPLATE(PartyID)}
            end}
        ],
        C
    ),
    ValidUntil = woody_deadline:to_binary(woody_deadline:from_timeout(100000)),
    TemplateToken = create_template_token(PartyID, ValidUntil),
    Ticket = create_transfer_ticket(TemplateToken),
    InvalidResourceToken = <<"v1.InvalidResourceToken">>,
    ValidResourceToken = create_card_token(),
    ?assertMatch(
        {error,
            {400, #{
                <<"errorType">> := <<"InvalidResourceToken">>,
                <<"name">> := <<"BankCardSenderResourceParams">>
            }}},
        create_p2p_transfer_with_template_call_api(C, Ticket, InvalidResourceToken, ValidResourceToken)
    ),
    ?assertMatch(
        {error,
            {400, #{
                <<"errorType">> := <<"InvalidResourceToken">>,
                <<"name">> := <<"BankCardReceiverResourceParams">>
            }}},
        create_p2p_transfer_with_template_call_api(C, Ticket, ValidResourceToken, InvalidResourceToken)
    ).

-spec create_transfer_fail_resource_token_expire_test(config()) -> _.
create_transfer_fail_resource_token_expire_test(C) ->
    PartyID = ?config(party, C),
    _ = wapi_ct_helper:mock_services(
        [
            {bender_thrift, fun('GenerateID', _) -> {ok, ?GENERATE_ID_RESULT} end},
            {fistful_p2p_template, fun
                ('GetContext', _) -> {ok, ?DEFAULT_CONTEXT(PartyID)};
                ('Get', _) -> {ok, ?P2P_TEMPLATE(PartyID)}
            end}
        ],
        C
    ),
    ValidUntil = woody_deadline:to_binary(woody_deadline:from_timeout(100000)),
    TemplateToken = create_template_token(PartyID, ValidUntil),
    Ticket = create_transfer_ticket(TemplateToken),
    InvalidResourceToken = create_card_token(wapi_utils:deadline_from_timeout(0)),
    ValidResourceToken = create_card_token(),
    ?assertMatch(
        {error,
            {400, #{
                <<"errorType">> := <<"InvalidResourceToken">>,
                <<"name">> := <<"BankCardSenderResourceParams">>
            }}},
        create_p2p_transfer_with_template_call_api(C, Ticket, InvalidResourceToken, ValidResourceToken)
    ),
    ?assertMatch(
        {error,
            {400, #{
                <<"errorType">> := <<"InvalidResourceToken">>,
                <<"name">> := <<"BankCardReceiverResourceParams">>
            }}},
        create_p2p_transfer_with_template_call_api(C, Ticket, ValidResourceToken, InvalidResourceToken)
    ).

%% Utility
quote_p2p_transfer_with_template_call_api(C) ->
    quote_p2p_transfer_with_template_call_api(C, create_card_token(), create_card_token()).

quote_p2p_transfer_with_template_call_api(C, SenderToken, ReceiverToken) ->
    call_api(
        fun swag_client_wallet_p2_p_templates_api:quote_p2_p_transfer_with_template/3,
        #{
            binding => #{
                <<"p2pTransferTemplateID">> => ?STRING
            },
            body => #{
                <<"body">> => #{
                    <<"amount">> => ?INTEGER,
                    <<"currency">> => ?RUB
                },
                <<"sender">> => #{
                    <<"type">> => <<"BankCardSenderResource">>,
                    <<"token">> => SenderToken
                },
                <<"receiver">> => #{
                    <<"type">> => <<"BankCardReceiverResource">>,
                    <<"token">> => ReceiverToken
                }
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

create_p2p_transfer_with_template_call_api(C, Ticket) ->
    ResourceToken = create_card_token(),
    create_p2p_transfer_with_template_call_api(C, Ticket, ResourceToken, ResourceToken).

create_p2p_transfer_with_template_call_api(C, Ticket, SenderToken, ReceiverToken) ->
    Context = maps:merge(wapi_ct_helper:cfg(context, C), #{token => Ticket}),
    call_api(
        fun swag_client_wallet_p2_p_templates_api:create_p2_p_transfer_with_template/3,
        #{
            binding => #{
                <<"p2pTransferTemplateID">> => ?STRING
            },
            body => #{
                <<"body">> => #{
                    <<"amount">> => ?INTEGER,
                    <<"currency">> => ?RUB
                },
                <<"sender">> => #{
                    <<"type">> => <<"BankCardSenderResourceParams">>,
                    <<"token">> => SenderToken,
                    <<"authData">> => <<"session id">>
                },
                <<"receiver">> => #{
                    <<"type">> => <<"BankCardReceiverResourceParams">>,
                    <<"token">> => ReceiverToken
                },
                <<"contactInfo">> => #{
                    <<"email">> => <<"some@mail.com">>,
                    <<"phoneNumber">> => <<"+79990000101">>
                }
            }
        },
        Context
    ).

-spec call_api(function(), map(), wapi_client_lib:context()) -> {ok, term()} | {error, term()}.
call_api(F, Params, Context) ->
    {Url, PreparedParams, Opts} = wapi_client_lib:make_request(Context, Params),
    Response = F(Url, PreparedParams, Opts),
    wapi_client_lib:handle_response(Response).

create_template_token(PartyID, ValidUntil) ->
    Deadline = genlib_rfc3339:parse(ValidUntil, second),
    wapi_auth:issue_access_token(
        PartyID,
        {p2p_templates, ?STRING, #{<<"expiration">> => ValidUntil}},
        {deadline, Deadline}
    ).

create_transfer_ticket(TemplateToken) ->
    ValidUntil = woody_deadline:to_binary(woody_deadline:from_timeout(100000)),
    {ok, #{<<"token">> := Ticket}} = call_api(
        fun swag_client_wallet_p2_p_templates_api:issue_p2_p_transfer_ticket/3,
        #{
            binding => #{
                <<"p2pTransferTemplateID">> => ?STRING
            },
            body => #{
                <<"validUntil">> => ValidUntil
            }
        },
        wapi_ct_helper:get_context(TemplateToken)
    ),
    Ticket.

create_card_token() ->
    create_card_token(undefined).

create_card_token(TokenDeadline) ->
    wapi_crypto:create_resource_token(?RESOURCE, TokenDeadline).
