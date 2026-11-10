# mpc-relay

An authenticated STOMP-over-WebSocket ⇄ AMQP 0-9-1 bridge that knows the MPC cohort's topology. It lets MPC devices that can only open WebSockets (browsers, React Native, Node) join a RabbitMQ cohort when the broker cannot expose Web-STOMP, or should not.

It contains no MPC code and knows nothing about MPC. It knows three things: the exchange the cohort uses, the routing keys sessions use, and which keys a given device may subscribe and send to.

## When to use it, and when not

The device client is one implementation. It speaks STOMP over WebSocket either to RabbitMQ's own [Web-STOMP plugin](https://www.rabbitmq.com/docs/web-stomp) or to this relay, and the URL alone decides which. The relay reproduces the part of Web-STOMP's behaviour that client relies on, as measured on RabbitMQ 4.4.

| Situation | Use |
|---|---|
| Self-hosted RabbitMQ, devices trusted with broker credentials (development, closed networks) | RabbitMQ Web-STOMP directly |
| **Amazon MQ for RabbitMQ**, or any broker without the Web-STOMP plugin | mpc-relay |
| Broker credentials must not ship inside an app | mpc-relay |
| You need per-device identity, per-device ACLs, rate limits or token expiry enforced at the edge | mpc-relay |

## How it fits

```text
  devices (browser / React Native / Node)                     MPC agents
  ┌──────────┐  ┌──────────┐                           ┌─────────┐ ┌─────────┐
  │ device A │  │ device B │                           │ agent 0 │ │ agent 1 │
  └────┬─────┘  └────┬─────┘                           └────┬────┘ └────┬────┘
       │ wss://…/ws  │  STOMP 1.2 frames                    │ AMQP 0-9-1│
       │ JWT in CONNECT passcode                            │           │
  ┌────▼─────────────▼────┐ pooled AMQP connections, ┌──────▼───────────▼──────┐
  │       mpc-relay       │   one channel per device │  RabbitMQ / Amazon MQ   │
  │  verify JWT → ACL →   ├─────────────────────────►│  exchange <EXCHANGE>    │
  │  queue/bind/consume   │   (amqps://, rustls)     │  (topic, durable,       │
  └───────────────────────┘                          │   declared by agents)   │
                                                     └─────────────────────────┘
```

For each device and session the relay declares the same queue Web-STOMP would, `mpc.session.<sub>.<session>`: exclusive, auto-delete, non-durable. It binds that queue to `session.<session>.broadcast` and `session.<session>.node.<sub>`. The device sees one inbox per session, in publish order.

## Quick start

### With Docker Compose (relay + RabbitMQ)

```sh
docker compose -f deploy/docker-compose.yml up --build
```

That starts RabbitMQ (management UI on <http://localhost:15672>, `mpc`/`mpc`) and the relay on `ws://localhost:8080/ws`. A one-shot container declares the exchange `mpc.cohort`, standing in for the agents.

```sh
RELAY_URL=ws://localhost:8080/ws \
JWT_SECRET=change-me-to-at-least-32-random-bytes \
EXCHANGE=mpc.cohort \
node examples/stomp-smoke.mjs
```

[`examples/stomp-smoke.mjs`](examples/stomp-smoke.mjs) has no dependencies (Node ≥ 22). It mints a token, subscribes the way a device does, sends, and checks what comes back.

### With Docker

```sh
docker run --rm -p 8080:8080 \
  -e MPC_RELAY_AMQP_URL='amqps://user:pass@b-xxxx.mq.eu-west-1.amazonaws.com:5671/%2f' \
  -e MPC_RELAY_EXCHANGE=mpc.cohort \
  -e MPC_RELAY_JWKS_URL=https://auth.example.com/.well-known/jwks.json \
  ghcr.io/zafeguard/mpc-relay:latest
```

### From source

```sh
cargo build --release
MPC_RELAY_AMQP_URL=amqp://guest:guest@localhost:5672/%2f \
MPC_RELAY_EXCHANGE=mpc.cohort \
MPC_RELAY_JWT_SECRET=$(openssl rand -hex 32) \
./target/release/mpc-relay
```

### On Kubernetes

[`deploy/kubernetes.yaml`](deploy/kubernetes.yaml) contains a Secret, a Deployment (non-root, read-only root filesystem, liveness on `/healthz`, readiness on `/readyz`, resource requests) and a Service.

## Configuration

Everything is configured through environment variables. The relay **refuses to start** in four cases: a required value is missing, a value does not parse, a variable is set but empty, or an `MPC_RELAY_*` variable is one it does not know. The point is that a typo such as `MPC_RELAY_JWT_ISUER` must not silently turn off the check it was meant to enable.

Durations take `500ms`, `10s`, `5m` or `1h`; a bare number means seconds.

### Required

| Variable | Meaning |
|---|---|
| `MPC_RELAY_AMQP_URL` | `amqp://` or `amqps://` URL of the broker, including the vhost (`%2f` for `/`). TLS uses rustls with the system's CA store. |
| `MPC_RELAY_EXCHANGE` | The cohort's exchange. Must equal the agents' `rabbitmq.exchange`. The relay checks it exists but never declares it. |
| one key source | Exactly one of `MPC_RELAY_JWT_SECRET`, `MPC_RELAY_JWKS_URL` or `MPC_RELAY_AUTH=none`. See below. |

### Authentication

| Variable | Default | Meaning |
|---|---|---|
| `MPC_RELAY_JWT_SECRET` | – | Shared secret (≥ 32 bytes, used as raw bytes). Accepts HS256, HS384 and HS512. |
| `MPC_RELAY_JWKS_URL` | – | JWKS endpoint. Accepts RS256, ES256 (P-256) and EdDSA (Ed25519). Must be `https://`, except loopback addresses. |
| `MPC_RELAY_JWKS_REFRESH_INTERVAL` | `300s` | How often the JWKS is re-fetched. |
| `MPC_RELAY_JWKS_MIN_REFRESH_INTERVAL` | `10s` | A token whose `kid` is unknown triggers a re-fetch, at most once per this interval. |
| `MPC_RELAY_JWKS_ALLOW_HTTP` | `false` | Allow a non-loopback `http://` JWKS URL. Anyone on the network path could then substitute signing keys. |
| `MPC_RELAY_AUTH` | – | `none` disables verification and uses CONNECT's `login` as the device id. **Development only**: the relay warns loudly at startup and on every connection. |
| `MPC_RELAY_JWT_ISSUER` | – | Require this `iss`. |
| `MPC_RELAY_JWT_AUDIENCE` | – | Require this `aud` (a string, or an array containing it). |
| `MPC_RELAY_JWT_LEEWAY` | `30s` | Clock-skew allowance for `exp`, `nbf` and `iat`. |
| `MPC_RELAY_JWT_MAX_TTL` | – | Reject tokens whose `exp - iat` exceeds this. Makes `iat` required. |
| `MPC_RELAY_SUB_PATTERN` | – | Regular expression every token's `sub` must match **as a whole**. The relay anchors it as `^(?:…)$` itself, so `device-[0-9]+` does not accept `xdevice-1`. Checked at CONNECT; an invalid expression stops the relay at startup. **Set it in production**, e.g. `^device-[A-Za-z0-9_-]{1,64}$`; see [Security model](#security-model). |

### Network

| Variable | Default | Meaning |
|---|---|---|
| `MPC_RELAY_LISTEN` | `0.0.0.0:8080` | WebSocket and HTTP listener. |
| `MPC_RELAY_WS_PATH` | `/ws` | WebSocket endpoint path. |
| `MPC_RELAY_METRICS_LISTEN` | – | Serve `/metrics` on this separate address (and not on the main listener). |
| `MPC_RELAY_TLS_CERT`, `MPC_RELAY_TLS_KEY` | – | PEM certificate chain and private key: serve `wss://` directly. Usually TLS terminates at a load balancer instead. |
| `MPC_RELAY_AMQP_CONNECTION_NAME` | `mpc-relay` | Client-provided connection name shown in the broker's UI; pooled connections are named `<name>#0`, `<name>#1`, and so on. |
| `MPC_RELAY_AMQP_MAX_CONNECTIONS` | derived | Most AMQP connections the pool opens. By default it is derived so the pool can carry `MPC_RELAY_MAX_CONNECTIONS` clients: `ceil(MPC_RELAY_MAX_CONNECTIONS / (channel_max - 2))`, which is 5 with RabbitMQ's default `channel_max` of 2047. |

### Limits

| Variable | Default | Meaning |
|---|---|---|
| `MPC_RELAY_MAX_CONNECTIONS` | `10000` | Concurrent WebSockets. Beyond it the upgrade is answered with HTTP 503. |
| `MPC_RELAY_MAX_SUBSCRIPTIONS` | `16` | Subscriptions per connection (a session uses two). |
| `MPC_RELAY_MAX_FRAME_BYTES` | `4194304` | Largest STOMP frame (headers + body). |
| `MPC_RELAY_SEND_RATE` | `200` | Token-bucket refill per second, per connection, for SEND, SUBSCRIBE and UNSUBSCRIBE. |
| `MPC_RELAY_SEND_BURST` | `400` | Token-bucket capacity. |
| `MPC_RELAY_CONNECT_TIMEOUT` | `10s` | Time allowed between the WebSocket opening and CONNECT. |
| `MPC_RELAY_IDLE_TIMEOUT` | `300s` | Close a connection that has sent nothing at all (no frame, heart-beat or pong) for this long. |
| `MPC_RELAY_PING_INTERVAL` | `20s` | WebSocket ping interval. Must be shorter than the idle timeout. |
| `MPC_RELAY_WRITE_TIMEOUT` | `30s` | Give up on a client that does not accept data for this long. |
| `MPC_RELAY_PREFETCH` | `64` | AMQP prefetch per subscription: deliveries in flight towards one client before the broker holds the rest. |
| `MPC_RELAY_SHUTDOWN_GRACE` | `20s` | On SIGTERM, how long clients get to leave by themselves before being told `server shutting down`. |

### Logging

| Variable | Default | Meaning |
|---|---|---|
| `RUST_LOG` | `info` | Standard `tracing` filter, such as `mpc_relay=debug`. |
| `MPC_RELAY_LOG_FORMAT` | `text` | `json` for one JSON object per line. |

Tokens, the JWT secret and broker passwords are never logged.

## Tokens

The JWT goes in CONNECT's `passcode` header; `login` is ignored. The algorithm set is fixed by the key source and never by the token. `alg: none` is always rejected. A JWKS key is only ever used with the one algorithm its key type implies (RSA → RS256, P-256 → ES256, Ed25519 → EdDSA), and symmetric `oct` keys in a JWKS are ignored.

| Claim | | Meaning |
|---|---|---|
| `sub` | required | The device's node id: 1–255 bytes, no `*`, `#`, `/`, whitespace or control characters. A device may receive only on its own `sub`. |
| `exp` | required | Expiry. The connection is closed with `ERROR token expired` when it passes, even mid-session. |
| `nbf` | optional | Not before. |
| `iat` | optional | Issued at. Required if `MPC_RELAY_JWT_MAX_TTL` is set; a future `iat` is rejected. |
| `iss`, `aud` | optional | Checked when the relay is configured to check them. |
| `sessions` | optional | Array of session UUIDs. When present, SUBSCRIBE and SEND are restricted to those sessions. Present but not an array of UUIDs (including `null`) is rejected, never read as "unrestricted". |

Minting one in Node.js with [`jose`](https://github.com/panva/jose):

```js
import { SignJWT } from 'jose'

// HS256 with the relay's MPC_RELAY_JWT_SECRET
const secret = new TextEncoder().encode(process.env.MPC_RELAY_JWT_SECRET)
const token = await new SignJWT({ sessions: [sessionId] })
  .setProtectedHeader({ alg: 'HS256' })
  .setSubject(deviceId)            // the device's node id
  .setIssuedAt()
  .setExpirationTime('10m')        // keep it short; the relay enforces exp mid-connection
  .setIssuer('https://auth.example.com')   // if MPC_RELAY_JWT_ISSUER is set
  .setAudience('mpc-relay')                // if MPC_RELAY_JWT_AUDIENCE is set
  .sign(secret)

// or, with keys published as a JWKS (MPC_RELAY_JWKS_URL):
//   const key = await importPKCS8(pem, 'EdDSA')
//   ... .setProtectedHeader({ alg: 'EdDSA', kid: 'key-2026-11' }).sign(key)
```

Then, on the device:

```js
ws.send(`CONNECT\naccept-version:1.2\nhost:/\npasscode:${token}\nheart-beat:0,0\n\n\0`)
```

## Security model

The relay is a security boundary in front of the broker. Devices never hold broker credentials. Everything a device can do is decided by its token and the fixed ACL below.

* **Authentication.** Every connection presents a JWT, verified against a configured secret or JWKS, before anything touches the broker. Failures are answered with a bare `ERROR authentication failed`. The reason goes to logs and to `mpc_relay_auth_failures_total{reason}`, never to the client.
* **Authorisation.** Only the configured exchange is reachable; every other destination type is refused, as are wildcards (`*`, `#`) in routing keys. A device may **subscribe** only to `session.<S>.broadcast` and `session.<S>.node.<its sub>`, through the queue `mpc.session.<its sub>.<S>`. It may **send** to `session.<S>.broadcast` or `session.<S>.node.<any node>`. `<S>` must be a canonical lowercase UUID. The `sessions` claim narrows both.
* **Exclusivity.** Many devices share each of the relay's AMQP connections, so the broker cannot tell two devices apart. The relay therefore enforces queue exclusivity itself, process-wide across its whole pool: a second connection subscribing with a queue name another connection holds gets `ERROR resource locked`, as RabbitMQ answers RESOURCE_LOCKED across connections. Across relay instances, each has its own AMQP connections, so the broker's own check applies.
* **Limits.** Connections, subscriptions, frame size, frame rate, connect and idle timeouts and write timeouts are all bounded. Deliveries are acknowledged only after they are written to the socket, so a slow client is held back by the broker's prefetch window, not buffered in the relay's memory.
* **Token lifetime.** `exp` is enforced for the life of the connection, not only at CONNECT. Use short-lived tokens and `MPC_RELAY_JWT_MAX_TTL`.
* **Configuration.** Unknown or empty `MPC_RELAY_*` variables are fatal, an HMAC secret must be at least 32 bytes, and a plain-`http` JWKS needs an explicit override.

What the token issuer must get right:

* `sub` values must be unique per device and must **never** equal an agent's node id. The relay cannot tell an agent's node id from a device's: both are just node ids in routing keys. So a device token whose `sub` is an agent's id would be allowed to subscribe to `session.<S>.node.<that agent>` and its queue name, and receive that agent's unicast traffic. While the agent holds its queue, the broker refuses the second consumer with RESOURCE_LOCKED; when the agent is not connected, nothing does.

  Set **`MPC_RELAY_SUB_PATTERN`** so that the relay itself enforces the split, rather than trusting every issuer to. Name devices and agents from disjoint namespaces (devices `device-…`, agents `agent-…`, say) and set the pattern to the device namespace only, for example `^device-[A-Za-z0-9_-]{1,64}$`. A token claiming an agent's id is then refused at CONNECT with `authentication failed` (reason `sub_not_allowed` in metrics and logs), however it was issued.
* Any node may send to any node's unicast key within an allowed session; that is how devices reach agents. The MPC protocol's own message authentication is what makes a forged message harmless. The relay does not replace it.

There are no cookies or ambient credentials, so cross-site WebSocket hijacking does not apply and the relay does not check `Origin`.

## Protocol subset

STOMP 1.2 (1.1 framing accepted) over WebSocket at `MPC_RELAY_WS_PATH`.

* **Subprotocols** `v12.stomp`, `v11.stomp`, `stomp`: the first one the client offers is selected. A client that offers none is accepted.
* **Framing.** Frames may arrive as text or binary messages; one message may hold several frames or part of one. Bare EOLs between frames are heart-beats and are ignored. `content-length` is honoured, so a body may then contain NUL. Header escaping (`\r` `\n` `\c` `\\`) applies on every frame except CONNECT and CONNECTED. If a header repeats, the first occurrence wins.
* **Outbound** frames are sent as text messages (as Web-STOMP does) when they are valid UTF-8, and as binary messages when the body is not.

| Client frame | Behaviour |
|---|---|
| `CONNECT` / `STOMP` | `accept-version` must include 1.1 or 1.2; `passcode` is the JWT; `host` and `login` are ignored. Must arrive within the connect timeout. Answered with `CONNECTED` (`version`, `server:mpc-relay/<version>`, `heart-beat:0,0`). Liveness is kept with WebSocket pings, not STOMP heart-beats. |
| `SUBSCRIBE` | `id`, `destination` and `x-queue-name` are required; `ack` must be absent or `auto`. Declares the session queue (idempotent: the second SUBSCRIBE of a session reuses it), binds it, and starts one consumer per subscription id. |
| `UNSUBSCRIBE` | `id`. Cancels that subscription's consumer. When a queue's last consumer goes, the broker auto-deletes it, as with Web-STOMP. |
| `SEND` | `destination`, optional `content-type`, `content-length`, `receipt`. Publishes the body bytes unchanged; `content-type` becomes the AMQP `content_type`. |
| `DISCONNECT` | Optional `receipt`: `RECEIPT`, then close. |
| `ACK` `NACK` `BEGIN` `COMMIT` `ABORT`, anything else | `ERROR not supported`. |

**Ordering and receipts.** Frames on one connection are processed strictly in order. Each frame's broker-side effects are complete before the next frame is acted on: queue declared, binding made, consumer started or cancelled, publish sent. So a `RECEIPT` vouches for every earlier frame on the connection, not only its own.

* For `SUBSCRIBE`, the `RECEIPT` is sent only once the queue is declared, the binding exists and the consumer has started.
* For `UNSUBSCRIBE`, it is sent once the broker has confirmed the cancel.
* For `SEND`, it is sent after the broker's publisher confirm.

A device can send `SUBSCRIBE` (broadcast) then `SUBSCRIBE` (unicast, with `receipt`) and treat that one `RECEIPT` as proof that both bindings exist.

**Delivery.** Messages arrive in channel order, which for one session is publish order. One queue with two consumers means the `subscription` header alternates between the two ids regardless of routing key, exactly as on Web-STOMP; treat every `MESSAGE` as one inbox. `MESSAGE` carries `subscription`, `message-id`, `destination` (`/exchange/<exchange>/<routing key>`), `redelivered`, `content-type` (if the AMQP message had one), `content-length`, and the body exactly as published.

**Errors.** Every `ERROR` is followed by closing the connection. The `message` header is one of:

| `message` | Cause |
|---|---|
| `authentication failed` | Token missing, invalid, expired, wrong issuer or audience, and so on. |
| `access refused` | Destination, routing key, queue name or session not allowed. The body says which. |
| `resource locked` | Another connection holds that session queue. |
| `token expired` | `exp` passed during the connection. |
| `not supported` | Transactions, ACK/NACK, client ack modes, unknown commands. |
| `frame too large`, `malformed frame` | Framing violations. |
| `rate limit exceeded`, `too many subscriptions` | Limits. |
| `too many connections` | Every AMQP connection the relay's pool may open is full. |
| `connect timeout`, `idle timeout` | Timeouts. |
| `not connected`, `already connected`, `unsupported protocol version`, `missing header`, `duplicate subscription id`, `subscription not found` | Protocol misuse. |
| `broker unavailable` | The broker connection is down, the exchange does not exist yet, or the broker closed this client's channel. |
| `server shutting down` | The relay is stopping; reconnect to another instance. |

## Operations

| Endpoint | Meaning |
|---|---|
| `GET /healthz` | 200 while the process is up. |
| `GET /readyz` | 200 when at least one pooled AMQP connection is up and sees the exchange (checked with a passive declare on connect and periodically), JWKS keys are loaded, and the relay is not draining. Otherwise 503. The JSON body says which condition failed, how many AMQP connections are open, and the pool's cap. |
| `GET /metrics` | Prometheus text format, on the main listener or on `MPC_RELAY_METRICS_LISTEN`. |

Metrics: `mpc_relay_connections_active`, `mpc_relay_connections_total`, `mpc_relay_auth_failures_total{reason}`, `mpc_relay_frames_total{direction,command}`, `mpc_relay_publishes_total`, `mpc_relay_deliveries_total`, `mpc_relay_errors_total{reason}`, `mpc_relay_broker_connected` (1 while any pooled connection is up), plus `mpc_relay_amqp_connections` (open), `mpc_relay_amqp_pool_size` (opened so far) and `mpc_relay_amqp_channels_in_use` (sessions placed). Label values come from fixed sets, never from client input.

**Broker loss.** Each pooled connection is supervised on its own. When one drops, exactly the clients placed on it get `ERROR broker unavailable` and are closed; clients on the other connections are untouched. The lost connection reconnects independently with capped exponential backoff (0.5 s doubling to 30 s, with jitter). `/readyz` turns 503 only when no connection is up. Devices reconnect and resubscribe; their old exclusive queues died with the old connection.

**Shutdown** (SIGTERM or SIGINT). `/readyz` turns 503 and new WebSockets are refused. Connected clients get `MPC_RELAY_SHUTDOWN_GRACE` to finish on their own. The rest receive `ERROR server shutting down`. Their queues are deleted, and the AMQP connection is closed.

## Scaling

The relay is stateless. Run as many instances as you like behind any TCP or HTTP load balancer that supports WebSockets.

* A client is pinned to the instance that accepted its WebSocket for the life of that connection. No sticky sessions or shared state are needed.
* A device that reconnects may land anywhere. Exclusivity of a session queue across instances is enforced by the broker itself.
* Set the load balancer's idle timeout above `MPC_RELAY_PING_INTERVAL`. The relay's pings are the traffic that keeps idle WebSockets open.
* Each client session needs **one AMQP channel**, and one AMQP connection carries at most the broker's `channel_max` channels (2047 by default on RabbitMQ). So each instance keeps a **pool** of AMQP connections:
  * The first is opened at startup and the rest lazily, when every live connection is full.
  * A session goes on the first live connection with a free channel. Two channels per connection are kept back for the relay's own short-lived channels.
  * The pool is capped so its total capacity matches `MPC_RELAY_MAX_CONNECTIONS`, or at `MPC_RELAY_AMQP_MAX_CONNECTIONS` if set. When every connection it may open is full, CONNECT is answered with `ERROR too many connections`.
  * The negotiated `channel_max`, per-connection capacity and cap are logged as each connection opens. Mind the broker's own per-user or per-vhost connection limits when sizing.

## Limitations

* Only the subset above. Destinations other than `/exchange/<configured exchange>/<session key>`, transactions, client acknowledgements, STOMP heart-beats (replaced by WebSocket pings), and arbitrary STOMP headers mapped to AMQP properties are not supported.
* Delivery is at-most-once towards a client that disconnects mid-stream: its queue is deleted with it, as with Web-STOMP.
* Within one connection, frames are processed one at a time. A SEND with a receipt waits for the publisher confirm before the next frame is read (about one broker round trip).
* JWKS keys: RSA (RS256), EC P-256 (ES256) and Ed25519 (EdDSA) only.
* Pooled AMQP connections opened for a peak stay open (and reconnect) after the peak passes; they are not retired when idle.
* A STOMP frame larger than the WebSocket message limit (frame limit + 64 KiB) is refused before it is buffered and answered with `ERROR frame too large`. A client still writing a very large message when that happens can lose the ERROR to the TCP reset, and sees only the connection close.
* The relay does not see client IPs behind a proxy (no `X-Forwarded-For` handling); its logs show the proxy's address.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                     # unit tests; broker tests skip themselves

# against a real broker:
docker run -d --name rabbit -e RABBITMQ_DEFAULT_USER=mpc -e RABBITMQ_DEFAULT_PASS=mpc \
  -p 5672:5672 -p 15672:15672 rabbitmq:4-management-alpine
MPC_RELAY_TEST_AMQP_URL='amqp://mpc:mpc@127.0.0.1:5672/%2f' \
MPC_RELAY_TEST_MGMT_URL='http://mpc:mpc@127.0.0.1:15672' \
cargo test
```

The broker tests run only when `MPC_RELAY_TEST_AMQP_URL` is set. Once it is set, an unreachable broker fails them rather than skipping. `MPC_RELAY_TEST_MGMT_URL` adds management-API assertions (queue flags, bindings, consumer counts where the broker exposes statistics) and the broker-loss test. `MPC_RELAY_TEST_LOG=mpc_relay=debug` prints the relay's logs.

Layout: `src/codec.rs` (STOMP framing), `src/auth.rs` (JWT), `src/acl.rs` (what a token may do), `src/bridge.rs` (one session onto one AMQP channel), `src/broker.rs` (the AMQP connection), `src/server.rs` (HTTP, WebSocket, TLS, lifecycle), `src/config.rs`, `src/metrics.rs`, `src/main.rs`.

## License

MIT. See [LICENSE](LICENSE).
