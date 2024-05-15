/**
 * kd_push
 */

import { serve } from '@hono/node-server'
import { serveStatic } from '@hono/node-server/serve-static'
// import { serveStatic } from 'hono/bun'
import { Hono } from 'hono'
import { showRoutes } from 'hono/dev'
import log from './libs/console.mjs'
import { readFileSync } from 'node:fs'
import { base64_to_base64url, buffer_to_base64, BuildJWT, Encrypt, GetAESGCMNonceAndCekAndContent, GetAES128GCMNonceAndCekAndContent, GetPublicKey, Sign, concatBuffer } from './libs/crypto.mjs'
import { saveKV } from './libs/db.mjs'
import { VAPID as vapidObject } from './db/vapid.mjs'
import { fileURLToPath } from 'node:url'
import { dirname } from 'node:path'
// import { loadModule } from 'cld3-asm'
// const TwitterCldr = require('twitter_cldr').load('en')

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const apiTemplate = (code = 403, message = 'Invalid Request', data = {}, version = 'push') => {
    return { code, message, data, version }
}

const kvDBPath = __dirname + '/db/kv.json'

log.info('', 'loading db from', kvDBPath)
let kv = JSON.parse(readFileSync(kvDBPath, 'utf-8'))

// log.info('', 'loading cld3 module')
// const cld3Module = await loadModule()

setInterval(async () => {
    const now = Date.now()
    const newKV = []
    for (const kvItem of Object.entries(kv)) {
        if (now - kvItem[1].last_used <= 1000 * 60 * 60 * 24 * 30 * 6) {
            newKV.push(kvItem)
        }
    }
    kv = Object.fromEntries(newKV)
    await saveKV(kvDBPath, kv)
}, 1000 * 60)

const app = new Hono()

app.use('*', async (c, next) => {
    await next()
    c.res.headers.append('Access-Control-Allow-Methods', '*')
})

app.use('/*', serveStatic({ root: './public' }))

app.get('/api/vapid', async (c) => {
    return c.json(
        apiTemplate(200, 'OK', {
            vapid: GetPublicKey(vapidObject.key)
        })
    )
})

app.post('/api/subscribe/', async (c) => {
    let uuid = crypto.randomUUID()

    let query = new Map()
    try {
        query = await c.req.formData()
    } catch {
        return c.json(apiTemplate(401, 'Invalid p256dh/auth/endpoint', { uuid }))
    }
    const p256dh = query.get('p256dh')
    const endpoint = query.get('endpoint')
    const auth = query.get('auth')

    if (!(p256dh && auth && endpoint)) {
        return c.json(apiTemplate(401, 'Invalid p256dh/auth/endpoint', { uuid }))
    }
    try {
        new URL(endpoint).origin
    } catch (e) {
        log.error(e)
        return c.json(apiTemplate(401, 'Invalid endpoint', { uuid }))
    }

    let max = 10

    while (kv[uuid] && max >= -1) {
        uuid = crypto.randomUUID()
        max--
    }
    if (max <= -1) {
        log.error('Failed to generate uuid')
        return c.json(apiTemplate(500, 'Failed to generate uuid', { uuid }))
    }
    kv[uuid] = {
        endpoint,
        auth,
        p256dh,
        uuid,
        last_used: Date.now(),
        count: 0
    }

    // log.log(kv)

    await saveKV(kvDBPath, kv)

    return c.json(apiTemplate(200, 'OK', { uuid }))
}).delete('/api/subscribe/:uuid', async (c) => {
    const uuid = c.req.param('uuid')
    if (kv[uuid]) {
        delete kv[uuid]
        await saveKV(kvDBPath, kv)
    }
    return c.json(apiTemplate(200, 'OK', true))
})

app.post('/api/push/:uuid?', async (c) => {
    const uuid = c.req.param('uuid')

    let query = new Map()
    try {
        query = await c.req.formData()
    } catch {}

    let p256dh = query.get('p256dh')
    let endpoint = query.get('endpoint')
    let auth = query.get('auth')
    let message = query.get('message')
    let testMessage = query.get('test') === '1'
    let encoding = query.get('encoding') === 'aes128gcm' ? 'aes128gcm' : 'aesgcm'

    if (!message && !testMessage) {
        return c.json(apiTemplate(403, 'Empty message', false))
    }

    if (!(endpoint && p256dh && auth)) {
        if (kv[uuid]) {
            p256dh = kv[uuid].p256dh
            endpoint = kv[uuid].endpoint
            auth = kv[uuid].auth

            kv[uuid].count++
            kv[uuid].last_used = Date.now()

            await saveKV(kvDBPath, kv)
        } else {
            return c.json(apiTemplate(401, 'Invalid p256dh/auth/endpoint', false))
        }
    }

    let aud = ''
    if (!endpoint) {
        return c.json(apiTemplate(403, 'No endpoint', false))
    } else {
        try {
            aud = new URL(endpoint).origin
            if (!aud) {
                return c.json(apiTemplate(403, 'Invalid endpoint', false))
            }
        } catch (e) {
            log.error(e)
            return c.json(apiTemplate(403, 'Invalid endpoint', false))
        }
    }

    const jwt = await BuildJWT(vapidObject, aud)

    // nonce and cek
    const eccKeyData = await crypto.subtle.generateKey(
        {
            name: 'ECDH',
            namedCurve: 'P-256'
        },
        true,
        ['deriveKey', 'deriveBits']
    )

    const salt = crypto.getRandomValues(new Uint8Array(16)).buffer

    let nonce, cek

    if (encoding === 'aes128gcm') {
        const d = await GetAES128GCMNonceAndCekAndContent(p256dh, auth, eccKeyData, salt)
        nonce = d.nonce
        cek = d.cek
    } else {
        const d = await GetAESGCMNonceAndCekAndContent(p256dh, auth, eccKeyData, salt)
        nonce = d.nonce
        cek = d.cek
    }

    const eccPublicKey = await crypto.subtle.exportKey('raw', eccKeyData.publicKey)

    let content = message ? message : 'This is a test content🔔✅🎉😺\n' + new Date() + ' (' + Date.now() + ')'
    // const identifier = cld3Module.create(0, 1000)
    // const lang = identifier.findLanguage(content)
    // identifier.dispose()

    // content = TwitterCldr.Bidi.from_string(content, { direction: 'RTL' }).toString()

    const timestamp = Date.now()

    const signPayload = new URLSearchParams({ content, timestamp: String(timestamp) }).toString()

    const sign = base64_to_base64url(buffer_to_base64(await Sign(vapidObject.key, new TextEncoder().encode(signPayload))))
    let payload = new Uint8Array(await Encrypt(nonce, cek, new TextEncoder().encode(JSON.stringify({ content, sign, timestamp })), encoding))

    let headers = {
        'Content-Type': 'application/octet-stream',
        'Content-Encoding': encoding,
        TTL: 60
    }
    if (encoding === 'aes128gcm') {
        headers['Authorization'] = 'vapid t=' + jwt + ',k=' + GetPublicKey(vapidObject.key)
        payload = concatBuffer(salt, new Uint8Array([0, 0, 16, 0]), new Uint8Array([65]), eccPublicKey, payload)
        headers['Content-Length'] = payload.byteLength
    } else {
        headers['Authorization'] = 'WebPush ' + jwt
        headers['Crypto-Key'] = 'dh=' + base64_to_base64url(buffer_to_base64(eccPublicKey)) + ';p256ecdsa=' + GetPublicKey(vapidObject.key)
        headers['Encryption'] = 'salt=' + base64_to_base64url(buffer_to_base64(salt))
        headers['Content-Length'] = payload.byteLength
    }

    try {
        const response = await fetch(endpoint, {
            headers,
            method: 'POST',
            body: payload
        })
        if ([404, 410].includes(response.status)) {
            delete kv[uuid]
            await saveKV(kvDBPath, kv)
        }
        return c.json(apiTemplate(response.status, 'OK', { status: response.status, text: await response.text() }))
    } catch (e) {
        log.error(e)
        return c.json(apiTemplate(500, 'Failed'))
    }
})

app.all('*', async (c) => {
    return c.json(apiTemplate())
})

const port = process.env.TINYPUSH_PORT || 3002
log.info(` Hello Hono🔥`)
log.info(` Server is running on port ${port}`)

showRoutes(app)

serve({
    fetch: app.fetch,
    port
})

// export default {
//     port,
//     fetch: app.fetch
// }
