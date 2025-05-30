-module(wapi_report_tests_SUITE).

-include_lib("common_test/include/ct.hrl").

-include_lib("fistful_reporter_proto/include/ffreport_reports_thrift.hrl").
-include_lib("wapi_wallet_dummy_data.hrl").
-include_lib("fistful_proto/include/fistful_fistful_thrift.hrl").
-include_lib("wapi_bouncer_data.hrl").

-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([init/1]).

-export([
    create_report_ok_test/1,
    get_report_ok_test/1,
    get_reports_ok_test/1,
    reports_with_wrong_party_ok_test/1,
    download_file_ok_test/1
]).

-define(EMPTY_RESP(Code), {error, {Code, #{}}}).

-type test_case_name() :: atom().
-type config() :: [{atom(), any()}].
-type group_name() :: atom().

-behaviour(supervisor).

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    {ok, {#{strategy => one_for_all, intensity => 1, period => 1}, []}}.

-spec all() -> [{group, test_case_name()}].
all() ->
    [
        {group, base}
    ].

-spec groups() -> [{group_name(), list(), [test_case_name()]}].
groups() ->
    [
        {base, [], [
            create_report_ok_test,
            get_report_ok_test,
            get_reports_ok_test,
            reports_with_wrong_party_ok_test,
            download_file_ok_test
        ]}
    ].

%%
%% starting/stopping
%%
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
    Party = genlib:bsuuid(),
    Config1 = [{party, Party} | Config],
    GroupSup = wapi_ct_helper:start_mocked_service_sup(?MODULE),
    _ = wapi_ct_helper_token_keeper:mock_user_session_token(Party, GroupSup),
    [{group_test_sup, GroupSup}, {context, wapi_ct_helper:get_context(?API_TOKEN)} | Config1];
init_per_group(_, Config) ->
    Config.

-spec end_per_group(group_name(), config()) -> _.
end_per_group(_Group, C) ->
    _ = wapi_ct_helper:stop_mocked_service_sup(?config(group_test_sup, C)),
    ok.

-spec init_per_testcase(test_case_name(), config()) -> config().
init_per_testcase(Name, C) ->
    C1 = wapi_ct_helper:makeup_cfg([wapi_ct_helper:test_case_name(Name), wapi_ct_helper:woody_ctx()], C),
    [{test_sup, wapi_ct_helper:start_mocked_service_sup(?MODULE)} | C1].

-spec end_per_testcase(test_case_name(), config()) -> ok.
end_per_testcase(_Name, C) ->
    _ = wapi_ct_helper:stop_mocked_service_sup(?config(test_sup, C)),
    ok.

%%% Tests
-spec create_report_ok_test(config()) -> _.
create_report_ok_test(C) ->
    _ = wapi_ct_helper_bouncer:mock_assert_party_op_ctx(<<"CreateReport">>, ?STRING, C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_report, fun
                ('GenerateReport', {#reports_ReportRequest{party_id = ExpectedPartyID}, _}) when
                    ExpectedPartyID =:= ?STRING
                ->
                    {ok, ?REPORT_ID};
                ('GenerateReport', _) ->
                    erlang:throw("Unexpected party id");
                ('GetReport', {ExpectedPartyID, _}) when ExpectedPartyID =:= ?STRING ->
                    {ok, ?REPORT};
                ('GetReport', _) ->
                    erlang:throw("Unexpected party id")
            end}
        ],
        C
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_reports_api:create_report/3,
        #{
            qs_val => #{
                <<"partyID">> => ?STRING
            },
            body => #{
                <<"reportType">> => <<"withdrawalRegistry">>,
                <<"fromTime">> => ?TIMESTAMP,
                <<"toTime">> => ?TIMESTAMP
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

-spec get_report_ok_test(config()) -> _.
get_report_ok_test(C) ->
    _ = wapi_ct_helper_bouncer:mock_assert_generic_op_ctx(
        [
            {report, genlib:to_binary(?INTEGER), #{party => ?STRING, files => [?STRING, ?STRING, ?STRING]}},
            {party, ?STRING, ?STRING}
        ],
        ?CTX_WAPI(#ctx_v1_WalletAPIOperation{
            id = <<"GetReport">>,
            party = ?STRING,
            report = genlib:to_binary(?INTEGER)
        }),
        C
    ),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_report, fun
                ('GetReport', {ExpectedPartyID, _}) when ExpectedPartyID =:= ?STRING ->
                    {ok, ?REPORT};
                ('GetReport', {ExpectedPartyID, _}) ->
                    erlang:throw({"Unexpected party id", ExpectedPartyID, ?STRING})
            end}
        ],
        C
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_reports_api:get_report/3,
        #{
            binding => #{
                <<"reportID">> => ?INTEGER
            },
            qs_val => #{
                <<"partyID">> => ?STRING
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

-spec get_reports_ok_test(config()) -> _.
get_reports_ok_test(C) ->
    ParamPartyID = genlib:bsuuid(),
    _ = wapi_ct_helper_bouncer:mock_assert_party_op_ctx(<<"GetReports">>, ParamPartyID, C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_report, fun
                ('GetReports', {#reports_ReportRequest{party_id = ExpectedPartyID}, _}) when
                    ExpectedPartyID =:= ParamPartyID
                ->
                    {ok, [
                        ?REPORT_EXT(pending, []),
                        ?REPORT_EXT(created, undefined),
                        ?REPORT_WITH_STATUS(canceled)
                    ]};
                ('GetReports', _) ->
                    erlang:throw("Unexpected party id")
            end}
        ],
        C
    ),
    {ok, _} = call_api(
        fun swag_client_wallet_reports_api:get_reports/3,
        #{
            qs_val => #{
                <<"partyID">> => ParamPartyID,
                <<"fromTime">> => ?TIMESTAMP,
                <<"toTime">> => ?TIMESTAMP,
                <<"type">> => <<"withdrawalRegistry">>
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

-spec reports_with_wrong_party_ok_test(config()) -> _.
reports_with_wrong_party_ok_test(C) ->
    PartyID = <<"WrongPartyID">>,
    _ = wapi_ct_helper_bouncer:mock_arbiter(_ = wapi_ct_helper_bouncer:judge_always_forbidden(), C),
    _ = wapi_ct_helper:mock_services(
        [
            {fistful_report, fun
                ('GenerateReport', _) -> {ok, ?REPORT_ID};
                ('GetReport', _) -> {ok, ?REPORT};
                ('GetReports', _) -> {ok, [?REPORT, ?REPORT, ?REPORT]}
            end}
        ],
        C
    ),
    ?EMPTY_RESP(401) = call_api(
        fun swag_client_wallet_reports_api:create_report/3,
        #{
            qs_val => #{
                <<"partyID">> => PartyID
            },
            body => #{
                <<"reportType">> => <<"withdrawalRegistry">>,
                <<"fromTime">> => ?TIMESTAMP,
                <<"toTime">> => ?TIMESTAMP
            }
        },
        wapi_ct_helper:cfg(context, C)
    ),
    ?EMPTY_RESP(401) = call_api(
        fun swag_client_wallet_reports_api:get_report/3,
        #{
            binding => #{
                <<"reportID">> => ?INTEGER
            },
            qs_val => #{
                <<"partyID">> => PartyID
            }
        },
        wapi_ct_helper:cfg(context, C)
    ),
    ?EMPTY_RESP(401) = call_api(
        fun swag_client_wallet_reports_api:get_reports/3,
        #{
            qs_val => #{
                <<"partyID">> => PartyID,
                <<"fromTime">> => ?TIMESTAMP,
                <<"toTime">> => ?TIMESTAMP,
                <<"type">> => <<"withdrawalRegistry">>
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

-spec download_file_ok_test(config()) -> _.
download_file_ok_test(C) ->
    _ = wapi_ct_helper_bouncer:mock_assert_op_ctx(<<"DownloadFile">>, C),
    _ = wapi_ct_helper:mock_services([{file_storage, fun('GenerateDownloadUrl', _) -> {ok, ?STRING} end}], C),
    {ok, _} = call_api(
        fun swag_client_wallet_downloads_api:download_file/3,
        #{
            binding => #{
                <<"fileID">> => ?STRING
            },
            qs_val => #{
                <<"expiresAt">> => ?TIMESTAMP
            }
        },
        wapi_ct_helper:cfg(context, C)
    ).

%%

-spec call_api(function(), map(), wapi_client_lib:context()) -> {ok, term()} | {error, term()}.
call_api(F, Params, Context) ->
    {Url, PreparedParams, Opts} = wapi_client_lib:make_request(Context, Params),
    Response = F(Url, PreparedParams, Opts),
    wapi_client_lib:handle_response(Response).
