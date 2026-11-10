// End-to-end smoke test for mpc-relay with no dependencies (Node >= 22:
// global WebSocket, node:crypto).
//
//   RELAY_URL=ws://localhost:8080/ws JWT_SECRET=... EXCHANGE=mpc.cohort \
//     node examples/stomp-smoke.mjs
//
// Mints an HS256 token, CONNECTs, SUBSCRIBEs twice with one shared
// x-queue-name (exactly as an MPC device does), SENDs to both of its keys
// and to another node's key, and checks that exactly its own two messages
// come back as MESSAGE frames, in order.

import { createHmac, randomUUID } from 'node:crypto'

const RELAY_URL = process.env.RELAY_URL ?? 'ws://localhost:8080/ws'
const SECRET = process.env.JWT_SECRET
const EXCHANGE = process.env.EXCHANGE ?? 'mpc.cohort'
const SUB = process.env.SUB ?? 'smoke-device'
const SESSION = process.env.SESSION ?? randomUUID()
const HOLD_MS = Number(process.env.HOLD_MS ?? 0)
if (!SECRET) throw new Error('JWT_SECRET is required')

// --- token: what an issuer would mint for one device -----------------------
const b64url = (b) => Buffer.from(b).toString('base64url')
function mintHs256(claims, secret) {
  const head = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const body = b64url(JSON.stringify(claims))
  const sig = createHmac('sha256', secret).update(`${head}.${body}`).digest('base64url')
  return `${head}.${body}.${sig}`
}
const now = Math.floor(Date.now() / 1000)
const token = mintHs256({ sub: SUB, iat: now, exp: now + 300, sessions: [SESSION] }, SECRET)

// --- minimal STOMP 1.2 framing -----------------------------------------------
const esc = (s) => String(s).replace(/\\/g, '\\\\').replace(/\r/g, '\\r').replace(/\n/g, '\\n').replace(/:/g, '\\c')
const unesc = (s) => s.replace(/\\(.)/g, (_, c) => ({ r: '\r', n: '\n', c: ':', '\\': '\\' })[c])
function frame(command, headers = {}, body = '') {
  const raw = command === 'CONNECT'
  const lines = Object.entries(headers).map(([k, v]) => (raw ? `${k}:${v}` : `${esc(k)}:${esc(v)}`))
  return `${command}\n${lines.join('\n')}\n\n${body}\0`
}
function parse(text) {
  const nl = text.indexOf('\n\n')
  const [command, ...lines] = text.slice(0, nl).split('\n')
  const headers = {}
  for (const l of lines) {
    const i = l.indexOf(':')
    const k = unesc(l.slice(0, i))
    if (!(k in headers)) headers[k] = unesc(l.slice(i + 1))
  }
  return { command, headers, body: text.slice(nl + 2) }
}

// --- the device flow -------------------------------------------------------
const bcast = `session.${SESSION}.broadcast`
const unicast = `session.${SESSION}.node.${SUB}`
const queue = `mpc.session.${SUB}.${SESSION}`
const dest = (key) => `/exchange/${EXCHANGE}/${key}`

const ws = new WebSocket(RELAY_URL, ['v12.stomp', 'v11.stomp'])
ws.binaryType = 'arraybuffer'
let buffer = ''
const waiters = []
const inbox = []
ws.onmessage = (ev) => {
  buffer += typeof ev.data === 'string' ? ev.data : new TextDecoder().decode(ev.data)
  let nul
  while ((nul = buffer.indexOf('\0')) >= 0) {
    const text = buffer.slice(0, nul).replace(/^[\r\n]+/, '')
    buffer = buffer.slice(nul + 1)
    if (!text) continue
    const f = parse(text)
    const w = waiters.findIndex((w) => w.match(f))
    if (w >= 0) waiters.splice(w, 1)[0].resolve(f)
    else inbox.push(f)
  }
}
const next = (match, what, ms = 5000) =>
  new Promise((resolve, reject) => {
    const i = inbox.findIndex(match)
    if (i >= 0) return resolve(inbox.splice(i, 1)[0])
    const t = setTimeout(() => reject(new Error(`timed out waiting for ${what}`)), ms)
    waiters.push({ match, resolve: (f) => (clearTimeout(t), resolve(f)) })
  })
const cmd = (c) => (f) => f.command === c || f.command === 'ERROR'
const receipt = (id) => (f) => (f.command === 'RECEIPT' && f.headers['receipt-id'] === id) || f.command === 'ERROR'
const ok = (f, want) => {
  if (f.command === 'ERROR') throw new Error(`ERROR ${f.headers.message}: ${f.body}`)
  if (want && f.command !== want) throw new Error(`expected ${want}, got ${f.command}`)
  return f
}
const log = (...a) => console.log(...a)

await new Promise((res, rej) => ((ws.onopen = res), (ws.onerror = () => rej(new Error('websocket failed')))))
log(`websocket open ${RELAY_URL} protocol=${ws.protocol || '(none)'}`)

ws.send(frame('CONNECT', { 'accept-version': '1.2', host: '/', login: SUB, passcode: token, 'heart-beat': '0,0' }))
const connected = ok(await next(cmd('CONNECTED'), 'CONNECTED'), 'CONNECTED')
log(`CONNECTED version=${connected.headers.version} server=${connected.headers.server} heart-beat=${connected.headers['heart-beat']}`)

ws.send(frame('SUBSCRIBE', { id: 'sub-0', destination: dest(bcast), ack: 'auto', 'x-queue-name': queue }))
ws.send(frame('SUBSCRIBE', { id: 'sub-1', destination: dest(unicast), ack: 'auto', 'x-queue-name': queue, receipt: 'subscribed' }))
ok(await next(receipt('subscribed'), 'RECEIPT subscribed'))
log(`SUBSCRIBEd sub-0 -> ${bcast}, sub-1 -> ${unicast}, shared queue ${queue}; RECEIPT received`)

const sends = [
  [bcast, 'hello broadcast'],
  [`session.${SESSION}.node.someone-else`, 'not for me'],
  [unicast, 'hello me'],
]
for (const [i, [key, body]] of sends.entries()) {
  ws.send(frame('SEND', { destination: dest(key), 'content-type': 'text/plain', 'content-length': Buffer.byteLength(body), receipt: `s${i}` }, body))
  ok(await next(receipt(`s${i}`), `RECEIPT s${i}`))
  log(`SEND ${key} "${body}" -> RECEIPT s${i}`)
}

const got = []
for (let i = 0; i < 2; i++) {
  const m = ok(await next(cmd('MESSAGE'), 'MESSAGE'), 'MESSAGE')
  got.push(m.body)
  log(`MESSAGE subscription=${m.headers.subscription} destination=${m.headers.destination} content-type=${m.headers['content-type']} content-length=${m.headers['content-length']} body="${m.body}"`)
}
await new Promise((r) => setTimeout(r, 500))
const stray = inbox.filter((f) => f.command === 'MESSAGE')
if (stray.length) throw new Error(`unexpected MESSAGE frames: ${JSON.stringify(stray)}`)
if (got[0] !== 'hello broadcast' || got[1] !== 'hello me') throw new Error(`wrong messages or order: ${JSON.stringify(got)}`)
log('no MESSAGE for the other node\'s unicast')

if (HOLD_MS) {
  log(`holding the connection for ${HOLD_MS} ms`)
  await new Promise((r) => setTimeout(r, HOLD_MS))
}
ws.send(frame('DISCONNECT', { receipt: 'bye' }))
ok(await next(receipt('bye'), 'RECEIPT bye'))
log('DISCONNECT -> RECEIPT bye')
ws.close()
log('SMOKE OK')
