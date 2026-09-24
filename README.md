# SoroBeacon 📡

**Monitoring and alerting for Soroban smart contracts.** Point SoroBeacon at
one or more contracts on Stellar, define rules ("this event fired", "an
edmitted value crossed a threshold", "more than N in M minutes"), and get alerts
on Discord, Slack, Telegram, Matrix, PagerDuty, Twilio SMS, email, or any webhook — with a
small dashboard to manage monitors
and review alert history.

Stellar has no good open-source way to watch a contract and get notified when
something happens on it. SoroBeacon aims to be that missing public good for
the Soroban ecosystem: a clean, well-tested core that is deliberately easy to
extend with new rule types and notification channels.

## How it works

```
Stellar RPC ──getEvents──▶ poller ──▶ decoder ──▶ rules engine ──▶ alerts ──▶ dispatcher ──▶ channels
                              │                                      │                          │
                              └── ingest_state ──────── Postgres ────┴───── delivery_attempts ──┘
```

- The **poller** calls the RPC's `getEvents` for every contract watched by an
  enabled monitor (batched across filters to respect RPC caps), following the
  pagination cursor and resuming from a checkpoint after restarts. Soroban
  RPCs only retain events for ~1–7 days, so SoroBeacon polls continuously and
  alerts in near-real-time.
- The **decoder** turns event topics/values into plain Go values, preferring
  the RPC's `xdrFormat: "json"` output and falling back to decoding base64
  XDR `ScVal`s locally (via the maintained `github.com/stellar/go-stellar-sdk`,
  which supersedes the deprecated `github.com/stellar/go`).
- The **rules engine** runs every enabled rule of every monitor watching the
  event's contract. Matches create alerts, deduplicated on
  `(rule_id, event_id)` so a rule can never fire twice for the same event.
- The **dispatcher** fans each alert out to the monitor's channels with
  retries and exponential backoff, recording every delivery attempt.

Reliability around the edges: each monitor carries a **poll priority**
(`low`/`normal`/`high`, default `normal`) and the poller schedules high-priority
contracts first with a weighted round-robin that never starves the low tier. A
chain **reorganisation** is detected by re-reading recently ingested ledger
hashes — a changed hash retracts the alerts derived from the orphaned range
(kept and flagged, never deleted), and an optional confirmation depth can hold
alerts until an event is buried. On Postgres, `alerts` is **range-partitioned
by month**, so retention drops whole expired partitions instead of deleting row
by row, and it can **archive** each batch to a directory or S3 before deleting
it so a failed archive blocks the delete.

## Quickstart

```sh
git clone <this repo> && cd sorobeacon
docker compose up --build -d
open http://localhost:8080        # dashboard
```

That starts Postgres and SoroBeacon against the Stellar **testnet** RPC.
Migrations run automatically on startup.

Running without Docker:

```sh
cp .env.example .env   # edit DATABASE_URL
make build
set -a; . ./.env; set +a; ./bin/sorobeacon
```

No Postgres on the box? Point `DATABASE_URL` at a file instead —
`DATABASE_URL=sqlite:///var/lib/sorobeacon/sorobeacon.db` starts a working
instance with no external service. SQLite backs a single instance well;
it serialises writes, so use Postgres for several writers or several instances.
See [capacity and scaling](docs/operations/scaling.md).

## Configuration

All configuration comes from environment variables. The complete
operator reference — every variable `internal/config` reads, grouped by
database / RPC / HTTP / polling / logging, with types, defaults, required
vs optional, secrets, and `SOURCE_MODE`-only notes — is
[docs/configuration.md](docs/configuration.md).

| Variable        | Default                                | Description                                  |
|-----------------|----------------------------------------|----------------------------------------------|
| `SOURCE_MODE`   | `rpc`                                  | `rpc` (standalone) or `sorotrail` (upstream) |
| `SOROTRAIL_URL` | —                                      | SoroTrail indexer base URL (upstream mode)   |
| `NETWORK`       | `testnet`                              | `testnet` \| `mainnet` \| `futurenet` \| `custom` |
| `RPC_URL`       | per network                            | Stellar RPC endpoint; overrides the preset   |
| `NETWORK_PASSPHRASE` | per network                       | Overrides the network passphrase             |
| `DATABASE_URL`  | *(required)*                           | Backend URL by scheme: Postgres (`postgres` / `postgresql`) or a single-file SQLite database (`sqlite:///path/to/sorobeacon.db`); validated at load |
| `DATABASE_MAX_CONNS` | pgx default                       | Pool max connections (`0` = driver default)  |
| `DATABASE_MIN_CONNS` | pgx default                       | Pool min connections (`0` = driver default)  |
| `DATABASE_MAX_CONN_LIFETIME` | pgx default                | Max connection lifetime (`0` = driver default) |
| `DATABASE_MAX_CONN_IDLE_TIME` | pgx default               | Max idle time (`0` = driver default)         |
| `POLL_INTERVAL` | `5s`                                   | How often to poll `getEvents` (min `1s`)     |
| `HTTP_ADDR`     | `:8080`                                | API + dashboard listen address (`host:port`) |
| `HTTP_MAX_BODY_BYTES` | `1048576` (1 MiB)                 | Max API write-body size; GET is unaffected   |
| `CORS_ALLOWED_ORIGINS` | _(empty, CORS off)_             | Comma-separated browser Origins; empty disables CORS |
| `MONITOR_SILENT_AFTER` | `24h`                            | Mark monitors silent on the dashboard after this much time since last match |
| `ALERT_RETENTION` | _(unset, keep forever)_             | How long to keep alerts; `90d`, `24h`. Postgres drops whole expired partitions |
| `ARCHIVE_URL`   | _(unset, off)_                         | Archive expired alerts before deletion (directory or `s3://bucket/prefix`) |
| `REORG_TRACKING_WINDOW` | `128`                        | Recent ledger hashes tracked for reorg detection; `0` disables |
| `REORG_CONFIRMATION_DEPTH` | `0`                       | Ledgers an event must be buried before it may alert |
| `LOG_LEVEL`     | `info`                                 | `debug` \| `info` \| `warn` \| `error`       |
| `READYZ_LAG_THRESHOLD` | `0` (disabled)                  | Fail `/readyz` when poller ledger lag exceeds this; 0 leaves probes unchanged |
| `RATE_LIMIT_RPS` | `0` (off)                             | Per-client API requests per second           |
| `RATE_LIMIT_BURST` | `ceil(RPS)` when enabled            | Per-client token-bucket size                 |
| `RATE_LIMIT_TRUST_FORWARDED` | `false`                  | Key clients by `X-Forwarded-For` (proxy only) |

### Notification Channels

Supported channels include [Discord](docs/channels/discord.md), [Slack](docs/channels/slack.md), [Telegram](docs/channels/telegram.md), [Matrix](docs/channels/matrix.md), [PagerDuty](docs/channels/pagerduty.md), [Twilio SMS](docs/channels/twilio.md), [Email](docs/channels/email.md), and generic [Webhooks](docs/channels/webhook.md).
