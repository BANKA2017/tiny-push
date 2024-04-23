/**
 * kd_push
 * We back now~
 */

import { serve } from '@hono/node-server'
import { serveStatic } from '@hono/node-server/serve-static'
//import { serveStatic } from 'hono/bun'
import { Hono } from 'hono'
import { showRoutes } from 'hono/dev'
import log from './libs/console.mjs'
import { readFileSync } from 'node:fs'
import { base64_to_base64url, buffer_to_base64, BuildJWT, Encrypt, GetAESGCMNonceAndCekAndContent, GetPublicKey, Sign } from './libs/crypto.mjs'
import { saveKV } from './libs/db.mjs'
import { VAPID } from './db/vapid.mjs'
const apiTemplate = (code = 403, message = 'Invalid Request', data = {}, version = 'push') => {
    return { code, message, data, version }
}

let vapidObject = VAPID
let kv = JSON.parse(readFileSync('./db/kv.json', 'utf-8'))

const app = new Hono()

app.use('*', async (c, next) => {
    await next()
    c.res.headers.append('Access-Control-Allow-Methods', '*')
})

app.use('/*', serveStatic({ root: './public' }))

app.get('/vapid', async (c) => {
    return c.json(
        apiTemplate(200, 'OK', {
            vapid: GetPublicKey(vapidObject.key)
        })
    )
})

app.put('/subscribe/:p256dh', async (c) => {
    const p256dh = c.req.param('p256dh')

    const query = await c.req.formData()
    const endpoint = query.get('endpoint')
    const auth = query.get('auth')

    if (!(p256dh && auth && endpoint)) {
        return c.json(apiTemplate(401, 'Invalid p256dh/auth/endpoint', false))
    }
    try {
        new URL(endpoint).origin
    } catch (e) {
        log.error(e)
        return c.json(apiTemplate(403, 'Invalid endpoint', false))
    }

    kv[p256dh] = {
        endpoint,
        auth,
        p256dh,
        last_used: Date.now(),
        count: 0
    }

    // log.log(kv)

    await saveKV('./db/kv.json', kv)

    return c.json(apiTemplate(200, 'OK', true))
}).delete('/subscribe/:p256dh', async (c) => {
    const p256dh = c.req.param('p256dh')

    const query = await c.req.formData()
    const endpoint = query.get('endpoint')
    const auth = query.get('auth')

    if (kv[p256dh] && kv[p256dh].endpoint === endpoint && kv[p256dh].auth === auth) {
        delete kv[p256dh]
        await saveKV('./db/kv.json', kv)
    }
    return c.json(apiTemplate(200, 'OK', true))
})

app.post('/push/:p256dh', async (c) => {
    const query = await c.req.formData()

    const p256dh = c.req.param('p256dh')
    let endpoint = query.get('endpoint')

    let auth = query.get('auth')
    let message = query.get('message')

    if (!(endpoint && p256dh && auth)) {
        if (kv[p256dh]) {
            endpoint = kv[p256dh].endpoint
            auth = kv[p256dh].auth
            message = query.get('message')
        } else {
            return c.json(apiTemplate(401, 'Invalid p256dh/auth/endpoint', false))
        }
    }

    if (!endpoint) {
        return c.json(apiTemplate(403, 'No endpoint', false))
    } else {
        try {
            vapidObject.aud = new URL(endpoint).origin
        } catch (e) {
            log.error(e)
            return c.json(apiTemplate(403, 'Invalid endpoint', false))
        }
    }

    const jwt = await BuildJWT(vapidObject)

    // nonce and cek
    const eccKeyData = await crypto.subtle.generateKey(
        {
            name: 'ECDH',
            namedCurve: 'P-256'
        },
        true,
        ['deriveKey', 'deriveBits']
    )

    const salt = base64_to_base64url(buffer_to_base64(crypto.getRandomValues(new Uint8Array(16)).buffer))

    const { nonce, cek, content: context } = await GetAESGCMNonceAndCekAndContent(p256dh, auth, eccKeyData, salt)

    const eccPublicKey = await crypto.subtle.exportKey('raw', eccKeyData.publicKey)

    const content = message ? message : 'Hello, here is TinyPush(仮)! this is a test content\n\n now is ' + new Date() + ' ' + Date.now()
    const sign = base64_to_base64url(buffer_to_base64(await Sign(vapidObject.key, new TextEncoder().encode(content))))
    //log.log(buffer_to_base64(nonce), buffer_to_base64(cek), buffer_to_base64(context), sign)
    const payload = new Uint8Array(await Encrypt(nonce, cek, new TextEncoder().encode(JSON.stringify({ content, sign, timestamp: Date.now() }))))

    try {
        const response = await fetch(endpoint, {
            headers: {
                Authorization: 'WebPush ' + jwt,
                'Content-Length': payload.byteLength,
                'Crypto-Key': 'dh=' + base64_to_base64url(buffer_to_base64(eccPublicKey)) + ';p256ecdsa=' + GetPublicKey(vapidObject.key),
                'Content-Type': 'application/octet-stream',
                'Content-Encoding': 'aesgcm',
                Encryption: 'salt=' + salt,
                TTL: 60
            },
            method: 'POST',
            body: payload
        })
        return c.json(apiTemplate(200, 'OK', response.status))
    } catch (e) {
        log.error(e)
        return c.json(apiTemplate(200, 'OK', 500))
    }
})

// app.get('/ws', async (c) => {
//     return c.json(apiTemplate())
// })

app.all('*', async (c) => {
    return c.json(apiTemplate())
})

const port = 3002
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
