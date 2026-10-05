# Synthetic portfolio demonstration

These commands demonstrate local contracts with synthetic fixtures. They do
not log in, call MAPIT/Telegram, invoke a model or demonstrate AWS deployment.
Run from the repository root after installing `.[test,agent,realtime]` in a
dedicated environment. Add `[windows-auth]` on Windows if needed for local
package availability; tests still use backend doubles.

```powershell
python -m mapit.health
python -m pytest -q tests/test_services.py tests/test_mcp_server.py tests/test_analytics.py
python -m pytest -q tests/test_realtime.py
python scripts/evaluate_agent_dataset.py
python -m pytest -q tests/test_agent_adapter.py tests/test_telegram_adapter.py tests/test_telegram_bot.py
```

| Capability | Evidence |
|---|---|
| Current status | Synthetic service/MCP fixtures and direct-status agent case |
| Yearly distance | UTC year buckets, native-unconfirmed units and partial-history caveats |
| Period comparison | Signed changes, missing/partial data and invalid period checks |
| Longest route | Deterministic tie-breaking and bounded route summaries |
| Realtime state | Fake socket normalization, freshness, reconnect and stop behavior |
| Natural-language agent contract | Twelve fixed synthetic cases in six classes; no generated model answers |
| Telegram query | Fake backend/sender, private allowlist, duplicate suppression and safe presentation |

The evaluator checks predetermined tool-call traces and structured answers.
Its 12/12 result is not an evaluation of a live model's accuracy. Prior live
acceptance remains separate in phase-specific status documents. No new live
demo is authorized by this guide. Do not substitute user routes, identifiers
or locations into committed fixtures or publish private CLI summaries.
