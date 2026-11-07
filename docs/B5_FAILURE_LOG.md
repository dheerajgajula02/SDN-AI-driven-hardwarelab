# B5: false-positive and failure log

Every time the AI layer (or our code around it) was wrong: what happened,
how we found it, what we changed, and the evidence. Newest last.

| # | Date | Part | What went wrong | How it was caught | Fix | Evidence |
|---|---|---|---|---|---|---|
| 1 | 2026-11-07 | llm_client | First live call: the model answered `{"health": "healthy", "switches_connected": ..., "links_up": ...}`, then on the repair try dropped the required `issues` field. Root cause was **ours**: the prompt never showed the model the schema, so it guessed field names. | The validator refused both answers (`'healthy' is not one of ['ok','degraded']`, `unexpected field`, `missing field "issues"`); the caller got an error, nothing was acted on. | The schema is now part of the system prompt; test L1 checks it is sent. Next live call: valid on the first try. | `logs/stepB2_llm_client/test_llm_client_run2.txt`, `run3.txt`; `logs/api_calls.jsonl` (run 2 lines) |
| 2 | 2026-11-07 | llm_client | First request refused by the provider: HTTP 400 `MissingSessionID` (opencode Go needs an `x-opencode-session` header). | HTTP 400 is not retried (permanent error); logged with the error text. | One session id per run (`lab9-<random>`), also written in each log line as `run`. | `logs/api_calls.jsonl` (first line) |
