# Telegram receipt state contract (offline proposal)

Status: pure state-machine proposal for review. This defines no DynamoDB adapter, table schema, retention period, webhook, Bot API write, or hosted-storage approval. Keep the existing in-memory Telegram adapters unchanged.

Current product scope (2026-10-05): Telegram is owner-only; multi-user access
is being prepared for the MCP, not for Telegram. Receipt replay protection is
still relevant to one user's bot, but this proposal neither implements durable
storage nor grants transport/deployment authority.

## Identity and scope

A receipt represents one inbound update for one bot. Its logical identity is a bot-scoped update identity (the bot namespace must not be confused with a tenant identity). A duplicate delivery maps to the same receipt key. The update body, command text, Telegram user/chat IDs, tokens, and response content are not receipt fields. A keyed digest may be used for the receipt key; key derivation/rotation and retention are separate decisions.

Telegram documents `update_id` as unique and sequential for ordinary updates, useful to recognize repeats and restore ordering; after a week without updates, the next ID may be random. Therefore do not use a globally increasing sequence assumption as the sole idempotency key. The accepted offline adapter already consumes an update before resolver/business/send and does not retry an ambiguous sender failure, but its in-memory set is not a durable guarantee.

## States and allowed transitions

```text
absent ──atomic first claim──> processing ──persist intent──> send_attempted
                                  │                              ├── positive Bot API success ──> sent
                                  │                              └── no confirmed success ─────> ambiguous
                                  └── deadline/stale claim ──> operator_review
```

- `processing`: the unique claim was committed before any tenant resolution, MAPIT business read, or Telegram send. It identifies an attempt generation, but stores no request payload. Only the process holding that exact generation may continue.
- `send_attempted`: persist this state before beginning the one external `sendMessage` call. It is a one-way boundary: after it is committed, no retry or takeover may send again.
- `sent`: terminal only after a positive success response from Telegram was observed and the receipt update was committed.
- `ambiguous`: terminal when the send was attempted but success was not positively confirmed (timeout, disconnect, cancellation, malformed response, or other uncertain result). Never retry the send automatically. A known non-success can also be conservatively recorded as unconfirmed if this model has no distinct definite-failure terminal state.
- `operator_review`: a `processing` attempt past its bounded business deadline is stale and requires explicit review. Do not let a lease expiry or a second Lambda take over business work. This proposal does not define the operator workflow.

Allowed transitions are strictly `absent → processing`, `processing → send_attempted`, `processing → operator_review`, and `send_attempted → sent | ambiguous`. Terminal states never return to `processing`; `send_attempted` never returns to a retryable state. A rejected transition returns a fixed category and performs no business or external send. There is no automatic transition from `operator_review` back to processing.

## Atomicity boundary

The offline repository need only define a pure reducer/validator for `(current_state, event) → (next_state | reject)`, with explicit attempt-generation matching. The later storage adapter must enforce these transitions atomically:

1. First claim succeeds only when the receipt key is absent. A conditional-write conflict is a duplicate/unknown claim, never permission to continue. Only the winner can perform tenant lookup or business work.
2. The send-intent write succeeds only if the same receipt is still `processing` for the same attempt generation. Call `sendMessage` only after that write is positively confirmed. An uncertain storage acknowledgement must be reconciled by readback; it must not be followed by a send unless the durable state is verified as this attempt's `send_attempted`.
3. A successful Telegram response may move the matching attempt to `sent`; any uncertain result may move it to `ambiguous`. The state update itself is conditional on the matching `send_attempted` generation. If its acknowledgement is uncertain, do not send again.
4. Duplicate callbacks for any existing state are acknowledged/suppressed according to the later transport policy, but do not repeat MAPIT work or Telegram send. The exact HTTP status decision is deliberately not part of this state-only contract.

AWS documents conditional `PutItem`/`UpdateItem` writes for this kind of compare-and-transition, and `TransactWriteItems` as atomic all-or-nothing across distinct items. A single receipt transition can be a conditional single-item write; use a transaction only if a separately accepted operation needs an atomic multi-item invariant. DynamoDB transactions cannot apply two actions to the same item in one transaction. A transaction or condition failure is not a reason to repeat business work. This is design evidence, not an instruction to create a table or use an SDK.

## Expiry and replay boundary

TTL is cleanup metadata, not an authorization condition or state transition. An expired TTL attribute does not make a receipt claimable: while the item remains present, the original key remains deduplicated. DynamoDB removes expired items asynchronously (typically within days), so TTL is not an exact timer. Once physical deletion occurs, an absent-key first claim could accept a very late duplicate. Consequently:

- no expiry timestamp may itself authorize replay, takeover, or state rollback;
- no claim of permanent deduplication is made;
- a future retention decision must define how long receipt/tombstone identity remains, account for Telegram's retry behavior and operational delays, and explicitly accept the residual replay risk after physical deletion;
- do not configure or rely on TTL until the user separately approves retention and deletion behavior.

Telegram's Bot API says a webhook delivery is retried after a non-2xx response and may eventually stop after a “reasonable amount” of attempts; it does not give a fixed retry-duration guarantee on the `setWebhook` contract. The Bot API also says `update_id` supports repeat/out-of-order detection. Neither statement supplies an exact receipt-retention period.

## Pure acceptance matrix

- Two concurrent first claims for one logical receipt: exactly one obtains `processing`; the loser cannot resolve a tenant, read MAPIT, or send.
- Existing `processing`, `send_attempted`, `sent`, `ambiguous`, or `operator_review`: duplicate causes no business call and no send.
- Stale/expired `processing`: reducer yields `operator_review`; no lease takeover or automatic retry.
- Wrong attempt generation or impossible transition: reject with a safe fixed category; state unchanged.
- Persisted `send_attempted` followed by positive send acknowledgement: `sent`; repeated update never sends again.
- Persisted `send_attempted` followed by exception, cancellation, timeout, or unknown outcome: `ambiguous`; repeated update never sends again.
- TTL timestamp elapsed but receipt still exists: duplicate remains suppressed. Physical deletion and later re-delivery is explicitly outside any permanence guarantee until retention is separately decided.
- Property tests cover every legal/illegal transition and prove reducer inputs/outputs contain no payload, identifiers, credentials, or answer text.

## Primary evidence

- [DynamoDB conditional expressions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html) — conditionally prevent overwrite and gate updates.
- [DynamoDB `TransactWriteItems`](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html) and [transaction behavior](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html) — atomic all-or-nothing writes, item uniqueness within a transaction, and transaction idempotency limits.
- [DynamoDB TTL](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html) and [expired-item behavior](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ttl-expired-items.html) — asynchronous physical deletion and behavior of expired-but-not-deleted items.
- [Telegram Bot API](https://core.telegram.org/bots/api) — `update_id`, webhook retries after non-2xx responses, and `getUpdates`/webhook mutual exclusion.
- Local context: [`telegram-hosted-gate.md`](telegram-hosted-gate.md), [`telegram-multiuser-expansion-contract.md`](telegram-multiuser-expansion-contract.md), `src/mapit/telegram_tenant_adapter.py`, and `src/mapit/telegram_adapter.py`.
