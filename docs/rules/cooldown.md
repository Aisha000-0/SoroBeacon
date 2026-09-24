# Rule cooldown

A busy contract plus a broad rule — `event_emitted` on `transfer` for a
popular token — produces one alert per event: a firehose that can exceed a
channel's rate limit and get the integration throttled or blocked. The
optional `cooldown` param suppresses repeat alerts from a rule for a window
after it fires, and reports how many matches it swallowed so the cooldown
never hides the scale of what happened.

`cooldown` is **cross-cutting**: it works with every rule type
([event_emitted](event-emitted.md), [value_threshold](value-threshold.md),
[token_event](token-event.md)) and sits alongside that rule's own params.

## Params

| Field | Required | Meaning |
| --- | --- | --- |
| `cooldown` | no | A Go duration string (`"30s"`, `"5m"`, `"1h"`). Omit for no cooldown. |

## Example

Alert at most once every five minutes for large transfers:

```sh
curl -s -X POST localhost:8080/api/v1/monitors/1/rules -d '{
  "type": "token_event",
  "params": {"event": "transfer", "min_amount": "1000000000", "cooldown": "5m"}
}'
```

## Behaviour

* The first match in a window fires normally and opens the window. Every
  further match from that rule inside the window is **counted and dropped** —
  no alert row, no delivery, and no channel rate limit spent.
* When the window closes, the next match fires and its payload (and the
  notification built from it) carries **`suppressed_since_last`**: how many
  matches the previous window dropped. So an operator sees the burst instead
  of a silent gap.
* The window is measured from when the rule last alerted, not from the event's
  ledger time, so a replayed or backfilled event can't reopen a stale window.
* Cooldown state lives in the database next to the dedup guard, under the same
  row lock, so it survives a poller restart and holds if two pollers run at
  once. It is not process memory.
* A rule without `cooldown` behaves exactly as before: every match alerts.

Replayed events are still deduplicated: the same `(rule, event)` never alerts
twice and never inflates the suppressed count.

## Validation

A `cooldown` that is not a valid, non-negative duration is rejected when the
rule is created or updated (HTTP `400` on `params.cooldown`), so a typo can't
silently leave a busy rule with no suppression.
