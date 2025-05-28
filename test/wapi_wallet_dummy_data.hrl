-define(STRING, <<"TEST">>).
-define(STRING2, <<"TEST2">>).
-define(RUB, <<"RUB">>).
-define(USD, <<"USD">>).
-define(BANKID_RU, <<"PUTIN">>).
-define(BANKID_US, <<"TRAMP">>).
-define(WALLET_TOOL, <<"TOOL">>).
-define(RESIDENCE_RUS, <<"RUS">>).
-define(RESIDENCE_DEU, <<"DEU">>).
-define(JSON, <<"{}">>).
-define(INTEGER, 10000).
-define(INTEGER_BINARY, <<"10000">>).
-define(TIMESTAMP, <<"2016-03-22T06:12:27Z">>).
-define(URL, <<"https://example.com">>).
-define(API_TOKEN, <<"letmein">>).
-define(CTX_NS, <<"wapi">>).
-define(DEFAULT_CONTEXT(PartyID), #{
    ?CTX_NS =>
        {obj, #{
            {str, <<"owner">>} => {str, PartyID},
            {str, <<"name">>} => {str, ?STRING},
            {str, <<"metadata">>} => {obj, #{{str, <<"somedata">>} => {str, ?STRING}}}
        }}
}).

-define(BOOLEAN, true).
-define(TEST_USER_REALM, <<"external">>).
-define(TEST_RULESET_ID, <<"test/api">>).

-define(DEFAULT_CONTEXT_NO_NAME(PartyID), #{
    ?CTX_NS =>
        {obj, #{
            {str, <<"owner">>} => {str, PartyID},
            {str, <<"metadata">>} => {obj, #{{str, <<"somedata">>} => {str, ?STRING}}}
        }}
}).

-define(DEFAULT_METADATA(), #{<<"somedata">> => {str, ?STRING}}).

-define(PAYMENT_SYSTEM_REF(ID), #'fistful_base_PaymentSystemRef'{id = ID}).
-define(PAYMENT_SERVICE_REF(ID), #'fistful_base_PaymentServiceRef'{id = ID}).
-define(CRYPTO_CURRENCY_REF(ID), #'fistful_base_CryptoCurrencyRef'{id = ID}).

-define(CASH, #'fistful_base_Cash'{
    amount = ?INTEGER,
    currency = #'fistful_base_CurrencyRef'{
        symbolic_code = ?RUB
    }
}).

-define(GET_INTERNAL_ID_RESULT, {
    'bender_GetInternalIDResult',
    ?STRING,
    {obj, #{{str, <<"context_data">>} => {str, ?STRING}}},
    undefined
}).

-define(GENERATE_ID_RESULT, ?GENERATE_ID_RESULT(?STRING)).

-define(GENERATE_ID_RESULT(ID), {
    'bender_GenerationResult',
    ID,
    undefined,
    undefined
}).

-define(BASE_FAILURE, #'fistful_base_Failure'{
    code = <<"account_limit_exceeded:amount:">>,
    sub = #'fistful_base_SubFailure'{
        code = <<"sub_code_level_1">>,
        sub = #'fistful_base_SubFailure'{code = <<"sub_code_level_2">>}
    }
}).
-define(BASE_FAILURE_WO_COLON, #'fistful_base_Failure'{
    code = <<"authorization_failed">>,
    sub = #'fistful_base_SubFailure'{
        code = <<"unknown">>
    }
}).

-define(WITHDRAWAL_STATUS, {pending, #wthd_status_Pending{}}).
-define(WITHDRAWAL_STATUS_FAILED, {failed, #wthd_status_Failed{failure = ?BASE_FAILURE}}).
-define(WITHDRAWAL_STATUS_FAILED_WO_COLON, {failed, #wthd_status_Failed{failure = ?BASE_FAILURE_WO_COLON}}).

-define(WITHDRAWAL_FAILED(PartyID), ?WITHDRAWAL(PartyID, ?WITHDRAWAL_STATUS_FAILED)).
-define(WITHDRAWAL_FAILED_WO_COLON(PartyID), ?WITHDRAWAL(PartyID, ?WITHDRAWAL_STATUS_FAILED_WO_COLON)).
-define(WITHDRAWAL(PartyID), ?WITHDRAWAL(PartyID, ?WITHDRAWAL_STATUS)).
-define(WITHDRAWAL(PartyID, Status), #wthd_WithdrawalState{
    id = ?STRING,
    wallet_id = ?STRING,
    destination_id = ?STRING,
    body = ?CASH,
    external_id = ?STRING,
    status = Status,
    created_at = ?TIMESTAMP,
    effective_final_cash_flow = #cashflow_FinalCashFlow{postings = []},
    sessions = [],
    adjustments = [],
    metadata = ?DEFAULT_METADATA(),
    context = ?DEFAULT_CONTEXT(PartyID),
    quote = ?WITHDRAWAL_QUOTE_STATE,
    party_id = PartyID,
    domain_revision = 123
}).

-define(WITHDRAWAL_QUOTE_STATE, #wthd_QuoteState{
    cash_from = ?CASH,
    cash_to = ?CASH,
    created_at = ?TIMESTAMP,
    expires_on = ?TIMESTAMP
}).

-define(WITHDRAWAL_QUOTE, #wthd_Quote{
    cash_from = ?CASH,
    cash_to = ?CASH,
    created_at = ?TIMESTAMP,
    expires_on = ?TIMESTAMP,
    operation_timestamp = ?TIMESTAMP,
    domain_revision = 123,
    route = #wthd_Route{
        provider_id = 123,
        terminal_id = 123
    },
    quote_data = {str, ?STRING}
}).

-define(WITHDRAWAL_EVENT(Change), #wthd_Event{
    change = Change,
    occured_at = ?TIMESTAMP,
    event_id = ?INTEGER
}).

-define(WITHDRAWAL_STATUS_CHANGE, {status_changed, #wthd_StatusChange{status = {pending, #wthd_status_Pending{}}}}).

-define(BLOCKING, unblocked).

-define(ACCOUNT, #account_Account{
    party_id = ?STRING,
    realm = live,
    currency = #'fistful_base_CurrencyRef'{
        symbolic_code = ?RUB
    },
    account_id = ?INTEGER
}).

-define(ACCOUNT_BALANCE, #account_AccountBalance{
    id = ?STRING,
    currency = #'fistful_base_CurrencyRef'{
        symbolic_code = ?RUB
    },
    expected_min = ?INTEGER,
    current = ?INTEGER,
    expected_max = ?INTEGER
}).

-define(BANK_CARD, #'fistful_base_BankCard'{
    bin_data_id = {i, ?INTEGER},
    token = ?STRING,
    bin = <<"424242">>,
    masked_pan = <<"4242">>,
    bank_name = ?STRING,
    issuer_country = rus,
    card_type = debit
}).

-define(BANK_CARD_PAN(Pan), ?BANK_CARD#'fistful_base_BankCard'{
    bin = ?BIN(Pan),
    masked_pan = ?LAST_DIGITS(Pan)
}).

-define(RESOURCE_BANK_CARD,
    {bank_card, #'fistful_base_ResourceBankCard'{
        bank_card = ?BANK_CARD
    }}
).

-define(DIGITAL_WALLET, #'fistful_base_DigitalWallet'{
    id = ?STRING,
    token = ?STRING,
    payment_service = #'fistful_base_PaymentServiceRef'{id = <<"nomoney">>},
    account_name = ?STRING,
    account_identity_number = ?STRING
}).

-define(RESOURCE_DIGITAL_WALLET,
    {digital_wallet, #'fistful_base_ResourceDigitalWallet'{
        digital_wallet = ?DIGITAL_WALLET
    }}
).

-define(BIN(CardNumber), string:slice(CardNumber, 0, 6)).

-define(LAST_DIGITS(CardNumber), string:slice(CardNumber, 12)).

-define(DESTINATION_STATUS, {authorized, #destination_Authorized{}}).

-define(DESTINATION(PartyID), ?DESTINATION(PartyID, ?RESOURCE_BANK_CARD)).

-define(DESTINATION(PartyID, Resource), #destination_DestinationState{
    id = ?STRING,
    name = ?STRING,
    account = ?ACCOUNT,
    resource = Resource,
    external_id = ?STRING,
    created_at = ?TIMESTAMP,
    context = ?DEFAULT_CONTEXT(PartyID),
    party_id = PartyID,
    realm = live
}).

-define(WITHDRAWAL_METHOD_BANK_CARD(ID),
    {bank_card, #'fistful_BankCardWithdrawalMethod'{payment_system = ?PAYMENT_SYSTEM_REF(ID)}}
).
-define(WITHDRAWAL_METHOD_DIGITAL_WALLET(ID), {digital_wallet, ?PAYMENT_SERVICE_REF(ID)}).
-define(WITHDRAWAL_METHOD_GENERIC(ID), {generic, ?PAYMENT_SERVICE_REF(ID)}).
-define(WITHDRAWAL_METHOD_CRYPTO_CURRENCY(ID), {crypto_currency, ?CRYPTO_CURRENCY_REF(ID)}).

-define(WITHDRAWAL_METHODS,
    ordsets:from_list([
        ?WITHDRAWAL_METHOD_BANK_CARD(<<"VISA">>),
        ?WITHDRAWAL_METHOD_BANK_CARD(<<"MIR">>),
        ?WITHDRAWAL_METHOD_DIGITAL_WALLET(<<"Webmoney">>),
        ?WITHDRAWAL_METHOD_DIGITAL_WALLET(<<"QIWI">>),
        ?WITHDRAWAL_METHOD_GENERIC(<<"SomeBank1">>),
        ?WITHDRAWAL_METHOD_GENERIC(<<"SomeBank2">>),
        ?WITHDRAWAL_METHOD_CRYPTO_CURRENCY(<<"LiteCoin">>)
    ])
).

-define(STAT_INVALID_EXCEPTION(Errors), #stat_InvalidRequest{errors = Errors}).
-define(STAT_BADTOKEN_EXCEPTION, #stat_BadToken{reason = ?STRING}).

-define(STAT_RESPONSE(Data), #stat_StatResponse{data = Data}).

-define(STAT_WITHDRAWALS,
    {withdrawals, [
        #stat_StatWithdrawal{
            id = ?STRING,
            created_at = ?TIMESTAMP,
            party_id = ?STRING,
            source_id = ?STRING,
            destination_id = ?STRING,
            external_id = ?STRING,
            amount = ?INTEGER,
            fee = ?INTEGER,
            currency_symbolic_code = ?RUB,
            status = {pending, #stat_WithdrawalPending{}}
        }
    ]}
).

-define(STAT_DEPOSITS,
    {deposits, [
        #stat_StatDeposit{
            id = ?STRING,
            created_at = ?TIMESTAMP,
            party_id = ?STRING,
            source_id = ?STRING,
            destination_id = ?STRING,
            amount = ?INTEGER,
            fee = ?INTEGER,
            currency_symbolic_code = ?RUB,
            status = {pending, #stat_DepositPending{}},
            description = ?STRING
        }
    ]}
).

-define(STAT_DESTINATIONS,
    {destinations, [
        #stat_StatDestination{
            id = ?STRING,
            party_id = ?STRING,
            realm = live,
            name = ?STRING,
            created_at = ?TIMESTAMP,
            is_blocked = ?BOOLEAN,
            currency_symbolic_code = ?RUB,
            resource = {bank_card, ?BANK_CARD},
            external_id = ?STRING
        },
        #stat_StatDestination{
            id = ?STRING,
            party_id = ?STRING,
            realm = live,
            name = ?STRING,
            created_at = ?TIMESTAMP,
            is_blocked = ?BOOLEAN,
            currency_symbolic_code = ?RUB,
            resource = {digital_wallet, ?DIGITAL_WALLET},
            external_id = ?STRING
        }
    ]}
).

-define(REPORT_ID, ?INTEGER).

-define(REPORT_EXT(Status, FilesList), #reports_Report{
    report_id = ?INTEGER,
    time_range = #reports_ReportTimeRange{
        from_time = ?TIMESTAMP,
        to_time = ?TIMESTAMP
    },
    created_at = ?TIMESTAMP,
    report_type = <<"withdrawalRegistry">>,
    status = Status,
    file_data_ids = FilesList
}).

-define(REPORT_WITH_STATUS(Status), ?REPORT_EXT(Status, [?STRING, ?STRING, ?STRING])).

-define(REPORT, ?REPORT_WITH_STATUS(created)).

-define(WITHDRAWAL_EVENT_FILTER, #webhooker_EventFilter{
    types = ordsets:from_list([
        {withdrawal, {started, #webhooker_WithdrawalStarted{}}},
        {withdrawal, {succeeded, #webhooker_WithdrawalSucceeded{}}},
        {withdrawal, {failed, #webhooker_WithdrawalFailed{}}}
    ])
}).

-define(DESTINATION_EVENT_FILTER, #webhooker_EventFilter{
    types = ordsets:from_list([
        {destination, {created, #webhooker_DestinationCreated{}}}
    ])
}).

-define(WEBHOOK_WITH_WALLET(EventFilter, WalletID), #webhooker_Webhook{
    id = ?INTEGER,
    party_id = ?STRING,
    wallet_id = WalletID,
    event_filter = EventFilter,
    url = ?URL,
    pub_key = ?STRING,
    enabled = false
}).

-define(WEBHOOK(EventFilter), ?WEBHOOK_WITH_WALLET(EventFilter, undefined)).

-define(FEES, #'fistful_base_Fees'{fees = #{operation_amount => ?CASH}}).
