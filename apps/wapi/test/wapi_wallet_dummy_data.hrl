-define(STRING, <<"TEST">>).
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
-define(CTX_NS, <<"com.rbkmoney.wapi">>).
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

-define(CASH, #'Cash'{
    amount = ?INTEGER,
    currency = #'CurrencyRef'{
        symbolic_code = ?RUB
    }
}).

-define(PROVIDER, #provider_Provider{
    id = ?STRING,
    name = ?STRING,
    residences = [?RESIDENCE_RUS, ?RESIDENCE_DEU]
}).

-define(GET_INTERNAL_ID_RESULT, {
    'bender_GetInternalIDResult',
    ?STRING,
    {obj, #{{str, <<"context_data">>} => {str, ?STRING}}},
    undefined
}).

-define(GENERATE_ID_RESULT, {
    'bender_GenerationResult',
    ?STRING,
    undefined,
    undefined
}).

-define(WITHDRAWAL_STATUS, {pending, #wthd_status_Pending{}}).

-define(WITHDRAWAL(PartyID), #wthd_WithdrawalState{
    id = ?STRING,
    wallet_id = ?STRING,
    destination_id = ?STRING,
    body = ?CASH,
    external_id = ?STRING,
    status = ?WITHDRAWAL_STATUS,
    created_at = ?TIMESTAMP,
    effective_final_cash_flow = #cashflow_FinalCashFlow{postings = []},
    sessions = [],
    adjustments = [],
    metadata = ?DEFAULT_METADATA(),
    context = ?DEFAULT_CONTEXT(PartyID)
}).

-define(WITHDRAWAL_QUOTE, #wthd_Quote{
    cash_from = ?CASH,
    cash_to = ?CASH,
    created_at = ?TIMESTAMP,
    expires_on = ?TIMESTAMP,
    operation_timestamp = ?TIMESTAMP,
    domain_revision = 123,
    party_revision = 123,
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
    id = ?STRING,
    identity = ?STRING,
    currency = #'CurrencyRef'{
        symbolic_code = ?RUB
    },
    accounter_account_id = ?INTEGER
}).

-define(ACCOUNT_BALANCE, #account_AccountBalance{
    id = ?STRING,
    currency = #'CurrencyRef'{
        symbolic_code = ?RUB
    },
    expected_min = ?INTEGER,
    current = ?INTEGER,
    expected_max = ?INTEGER
}).

-define(BANK_CARD, #'BankCard'{
    bin_data_id = {i, ?INTEGER},
    token = ?STRING,
    bin = <<"424242">>,
    masked_pan = <<"4242">>,
    bank_name = ?STRING,
    payment_system_deprecated = visa,
    issuer_country = rus,
    card_type = debit
}).

-define(BANK_CARD_PAN(Pan), ?BANK_CARD#'BankCard'{
    bin = ?BIN(Pan),
    masked_pan = ?LAST_DIGITS(Pan)
}).

-define(RESOURCE_BANK_CARD,
    {bank_card, #'ResourceBankCard'{
        bank_card = ?BANK_CARD
    }}
).

-define(DIGITAL_WALLET, #'DigitalWallet'{
    id = ?STRING,
    token = ?STRING,
    payment_service = #'PaymentServiceRef'{id = <<"Webmoney">>}
}).

-define(RESOURCE, {bank_card, ?BANK_CARD}).
-define(RESOURCE_DIGITAL_WALLET, {digital_wallet, ?DIGITAL_WALLET}).

-define(BIN(CardNumber), string:slice(CardNumber, 0, 6)).

-define(LAST_DIGITS(CardNumber), string:slice(CardNumber, 12)).

-define(DESTINATION_STATUS, {authorized, #dst_Authorized{}}).

-define(DESTINATION(PartyID), #dst_DestinationState{
    id = ?STRING,
    name = ?STRING,
    status = ?DESTINATION_STATUS,
    account = ?ACCOUNT,
    resource = ?RESOURCE_BANK_CARD,
    external_id = ?STRING,
    created_at = ?TIMESTAMP,
    context = ?DEFAULT_CONTEXT(PartyID)
}).

-define(WALLET(PartyID), #wlt_WalletState{
    id = ?STRING,
    name = ?STRING,
    blocking = ?BLOCKING,
    account = ?ACCOUNT,
    external_id = ?STRING,
    created_at = ?TIMESTAMP,
    metadata = ?DEFAULT_METADATA(),
    context = ?DEFAULT_CONTEXT(PartyID)
}).

-define(IDENTITY(PartyID),
    ?IDENTITY(PartyID, ?DEFAULT_CONTEXT(PartyID))
).

-define(IDENTITY(PartyID, Context), #idnt_IdentityState{
    id = ?STRING,
    name = ?STRING,
    party_id = ?STRING,
    provider_id = ?STRING,
    contract_id = ?STRING,
    metadata = ?DEFAULT_METADATA(),
    context = Context
}).

-define(STAT_INVALID_EXCEPTION(Errors), #fistfulstat_InvalidRequest{errors = Errors}).
-define(STAT_BADTOKEN_EXCEPTION, #fistfulstat_BadToken{reason = ?STRING}).

-define(STAT_RESPONCE(Data), #fistfulstat_StatResponse{data = Data}).

-define(STAT_WALLETS,
    {wallets, [
        #fistfulstat_StatWallet{
            id = ?STRING,
            identity_id = ?STRING,
            name = ?STRING,
            created_at = ?TIMESTAMP,
            currency_symbolic_code = ?RUB
        }
    ]}
).

-define(STAT_WITHDRAWALS,
    {withdrawals, [
        #fistfulstat_StatWithdrawal{
            id = ?STRING,
            created_at = ?TIMESTAMP,
            identity_id = ?STRING,
            source_id = ?STRING,
            destination_id = ?STRING,
            external_id = ?STRING,
            amount = ?INTEGER,
            fee = ?INTEGER,
            currency_symbolic_code = ?RUB,
            status = {pending, #fistfulstat_WithdrawalPending{}}
        }
    ]}
).

-define(STAT_DEPOSITS,
    {deposits, [
        #fistfulstat_StatDeposit{
            id = ?STRING,
            created_at = ?TIMESTAMP,
            identity_id = ?STRING,
            source_id = ?STRING,
            destination_id = ?STRING,
            amount = ?INTEGER,
            fee = ?INTEGER,
            currency_symbolic_code = ?RUB,
            status = {pending, #fistfulstat_DepositPending{}}
        }
    ]}
).

-define(STAT_DESTINATIONS,
    {destinations, [
        #fistfulstat_StatDestination{
            id = ?STRING,
            name = ?STRING,
            created_at = ?TIMESTAMP,
            is_blocked = ?BOOLEAN,
            identity = ?STRING,
            currency_symbolic_code = ?RUB,
            resource = ?RESOURCE,
            external_id = ?STRING,
            status = {unauthorized, #fistfulstat_Unauthorized{}}
        },
        #fistfulstat_StatDestination{
            id = ?STRING,
            name = ?STRING,
            created_at = ?TIMESTAMP,
            is_blocked = ?BOOLEAN,
            identity = ?STRING,
            currency_symbolic_code = ?RUB,
            resource = ?RESOURCE_DIGITAL_WALLET,
            external_id = ?STRING,
            status = {unauthorized, #fistfulstat_Unauthorized{}}
        }
    ]}
).

-define(STAT_IDENTITIES,
    {identities, [
        #fistfulstat_StatIdentity{
            id = ?STRING,
            name = ?STRING,
            created_at = ?TIMESTAMP,
            provider = ?STRING,
            is_blocked = ?BOOLEAN,
            external_id = ?STRING
        }
    ]}
).

-define(STAT_DEPOSIT_REVERTS,
    {deposit_reverts, [
        #fistfulstat_StatDepositRevert{
            id = ?STRING,
            wallet_id = ?STRING,
            source_id = ?STRING,
            status = {succeeded, #fistfulstat_DepositRevertSucceeded{}},
            body = ?CASH,
            created_at = ?TIMESTAMP,
            domain_revision = ?INTEGER,
            party_revision = ?INTEGER,
            reason = ?STRING,
            external_id = ?STRING,
            deposit_id = ?STRING
        }
    ]}
).

-define(STAT_DEPOSIT_ADJUSTMENTS_WO_CANGES_PLAN,
    ?STAT_DEPOSIT_ADJUSTMENTS(#fistfulstat_DepositAdjustmentChangesPlan{})
).

-define(STAT_DEPOSIT_ADJUSTMENTS_WITH_CANGES_PLAN,
    ?STAT_DEPOSIT_ADJUSTMENTS(
        #fistfulstat_DepositAdjustmentChangesPlan{
            new_cash = #fistfulstat_DepositAdjustmentCashChangePlan{amount = ?CASH, fee = ?CASH, provider_fee = ?CASH},
            new_status = #fistfulstat_DepositAdjustmentStatusChangePlan{
                new_status = {succeeded, #fistfulstat_DepositAdjustmentStatusChangePlanSucceeded{}}
            }
        }
    )
).

-define(STAT_DEPOSIT_ADJUSTMENTS(ChangesPlan),
    {deposit_adjustments, [
        #fistfulstat_StatDepositAdjustment{
            id = ?STRING,
            status = {succeeded, #fistfulstat_DepositAdjustmentSucceeded{}},
            changes_plan = ChangesPlan,
            created_at = ?TIMESTAMP,
            domain_revision = ?INTEGER,
            party_revision = ?INTEGER,
            external_id = ?STRING,
            operation_timestamp = ?TIMESTAMP,
            deposit_id = ?STRING
        }
    ]}
).

-define(IDENT_DOC,
    {russian_domestic_passport, #'identdocstore_RussianDomesticPassport'{
        issuer = ?STRING,
        issuer_code = ?STRING,
        issued_at = ?TIMESTAMP,
        birth_date = ?TIMESTAMP,
        birth_place = ?STRING,
        series = ?STRING,
        number = ?STRING,
        first_name = ?STRING,
        family_name = ?STRING,
        patronymic = ?STRING
    }}
).

-define(REPORT_ID, ?INTEGER).

-define(REPORT_EXT(Status, FilesList), #ff_reports_Report{
    report_id = ?INTEGER,
    time_range = #ff_reports_ReportTimeRange{
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
        {destination, {created, #webhooker_DestinationCreated{}}},
        {destination, {unauthorized, #webhooker_DestinationUnauthorized{}}},
        {destination, {authorized, #webhooker_DestinationAuthorized{}}}
    ])
}).

-define(WEBHOOK_WITH_WALLET(EventFilter, WalletID), #webhooker_Webhook{
    id = ?INTEGER,
    identity_id = ?STRING,
    wallet_id = WalletID,
    event_filter = EventFilter,
    url = ?URL,
    pub_key = ?STRING,
    enabled = false
}).

-define(WEBHOOK(EventFilter), ?WEBHOOK_WITH_WALLET(EventFilter, undefined)).

-define(W2W_TRANSFER(PartyID), #w2w_transfer_W2WTransferState{
    id = ?STRING,
    wallet_from_id = ?STRING,
    wallet_to_id = ?STRING,
    body = ?CASH,
    created_at = ?TIMESTAMP,
    domain_revision = ?INTEGER,
    party_revision = ?INTEGER,
    status = {pending, #w2w_status_Pending{}},
    external_id = ?STRING,
    metadata = ?DEFAULT_METADATA(),
    context = ?DEFAULT_CONTEXT(PartyID),
    effective_final_cash_flow = #cashflow_FinalCashFlow{
        postings = []
    },
    adjustments = []
}).

-define(FEES, #'Fees'{fees = #{operation_amount => ?CASH}}).
