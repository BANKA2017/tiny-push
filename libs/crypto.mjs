import crypto from 'crypto'
import log from './console.mjs'

export const ImportKey = (jwk, name = 'ECDH') => {
    return crypto.subtle.importKey(
        'jwk',
        jwk,
        {
            name,
            namedCurve: jwk.crv
        },
        true,
        jwk.key_ops
    )
}

export let GlobalJWT = {}

export const GetPrivateKey = (jwk) => jwk.d

let publicKeyCache = ''

export const GetPublicKey = (jwk) => {
    if (!publicKeyCache) {
        publicKeyCache = base64_to_base64url(buffer_to_base64(concatBuffer(new Uint8Array([4]).buffer, base64_to_buffer(base64url_to_base64(jwk.x)), base64_to_buffer(base64url_to_base64(jwk.y)))))
    }
    return publicKeyCache
}

export const BuildJWT = async (vapidObject = {}, aud = '') => {
    const now = Date.now()

    if (GlobalJWT[aud] && GlobalJWT[aud].content && GlobalJWT[aud].expire > now) {
        return GlobalJWT[aud].content
    }

    if (!(vapidObject.key && aud && vapidObject.sub)) {
        return ''
    }
    try {
        const info = {
            typ: 'JWT',
            alg: 'ES256'
        }
        const data = {
            aud,
            exp: Math.floor(now / 1000) + 60 * 60,
            sub: vapidObject.sub
        }
        const unsignedToken = base64_to_base64url(btoa(JSON.stringify(info))) + '.' + base64_to_base64url(btoa(JSON.stringify(data)))

        GlobalJWT[aud] = {
            content: unsignedToken + '.' + base64_to_base64url(buffer_to_base64(await Sign(vapidObject.key, new TextEncoder().encode(unsignedToken)))),
            expire: now + 30 * 60 * 1000
        }

        return GlobalJWT[aud].content
    } catch (e) {
        log.error(e)
        return ''
    }
}

export const Sign = async (jwk = {}, payload = new Uint8Array()) => {
    const key = await ImportKey(jwk, 'ECDSA')
    return await crypto.subtle.sign(
        {
            name: 'ECDSA',
            hash: {
                name: 'SHA-256'
            }
        },
        key,
        payload
    )
}

//https://stackoverflow.com/questions/21797299/convert-base64-string-to-arraybuffer
export const base64_to_buffer = (base64) => {
    let binaryString = atob(base64)
    let bytes = new Uint8Array(binaryString.length)
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i)
    }
    return bytes.buffer
}
//https://stackoverflow.com/questions/56846930/how-to-convert-raw-representations-of-ecdh-key-pair-into-a-json-web-key
export const hex_to_uintarray = (hex) => {
    const a = []
    for (let i = 0, len = hex.length; i < len; i += 2) {
        a.push(parseInt(hex.substr(i, 2), 16))
    }
    return new Uint8Array(a)
}
export const buffer_to_base64 = (buf) => {
    let binary = ''
    const bytes = new Uint8Array(buf)
    for (var i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i])
    }
    return btoa(binary)
}
export const base64_to_base64url = (base64) => base64.replaceAll('/', '_').replaceAll('+', '-').replaceAll('=', '')
export const base64url_to_base64 = (base64url) => base64url.replaceAll('_', '/').replaceAll('-', '+')
//https://stackoverflow.com/questions/40031688/javascript-arraybuffer-to-hex
export const buffer_to_hex = (buffer) => {
    // buffer is an ArrayBuffer
    return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, '0')).join('')
}
//https://gist.github.com/72lions/4528834
export const concatBuffer = (...buffer) => {
    const length = buffer.reduce((acc, cur) => acc + cur.byteLength, 0)
    let tmp = new Uint8Array(length)
    buffer.reduce((acc, cur) => {
        tmp.set(new Uint8Array(cur), acc)
        return acc + cur.byteLength
    }, 0)
    return tmp
}

export const ECDH = async (publicKey, privateKey) => {
    const ecdh_secret_CryptoKey = await crypto.subtle.deriveKey(
        {
            name: 'ECDH',
            public: publicKey
        },
        privateKey,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    )
    const ecdh_secret = await crypto.subtle.exportKey('raw', ecdh_secret_CryptoKey)
    return ecdh_secret
}

export const HmacSHA256 = async (key, data) => {
    const keyData = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'])
    return new Uint8Array(await crypto.subtle.sign('HMAC', keyData, data))
}
export const HKDF = async (key, ikm, info, length = -1) => {
    const tmpKey = await HmacSHA256(key, ikm)
    return (await HmacSHA256(tmpKey, info)).slice(0, length < 0 ? undefined : length)
}

export const GetAESGCMNonceAndCekAndContent = async (subscriptionPublicKeyStr, auth, eccKeyData, salt) => {
    const subscriptionPublicKeyBuffer = new Uint8Array(base64_to_buffer(base64url_to_base64(subscriptionPublicKeyStr)))
    const subscriptionPublicKey = await crypto.subtle.importKey(
        'raw',
        subscriptionPublicKeyBuffer,
        {
            name: 'ECDH',
            namedCurve: 'P-256'
        },
        true,
        []
    )
    const ecdh_secret = await ECDH(subscriptionPublicKey, eccKeyData.privateKey)

    const publishPublicKeyBuffer = await crypto.subtle.exportKey('raw', eccKeyData.publicKey)

    const auth_secret = base64_to_buffer(base64url_to_base64(auth))

    const context = concatBuffer(new TextEncoder().encode('P-256\0'), new Uint8Array([0, 65]), subscriptionPublicKeyBuffer, new Uint8Array([0, 65]), publishPublicKeyBuffer)

    const auth_info = new TextEncoder().encode('Content-Encoding: auth\0')
    const PRK_combine = await HmacSHA256(auth_secret, ecdh_secret)
    const IKM = await HmacSHA256(PRK_combine, concatBuffer(auth_info, new Uint8Array([1])))

    const PRK = await HmacSHA256(salt, IKM)
    const cek_info = concatBuffer(new TextEncoder().encode('Content-Encoding: aesgcm\0'), context)
    let cek = (await HmacSHA256(PRK, concatBuffer(cek_info, new Uint8Array([1])))).slice(0, 16)
    const nonce_info = concatBuffer(new TextEncoder().encode('Content-Encoding: nonce\0'), context)
    let nonce = (await HmacSHA256(PRK, concatBuffer(nonce_info, new Uint8Array([1])))).slice(0, 12)
    return { nonce, cek, context }
}

export const GetAES128GCMNonceAndCekAndContent = async (subscriptionPublicKeyStr, auth, eccKeyData, salt) => {
    const subscriptionPublicKeyBuffer = new Uint8Array(base64_to_buffer(base64url_to_base64(subscriptionPublicKeyStr)))
    const subscriptionPublicKey = await crypto.subtle.importKey(
        'raw',
        subscriptionPublicKeyBuffer,
        {
            name: 'ECDH',
            namedCurve: 'P-256'
        },
        true,
        []
    )
    const ecdh_secret = await ECDH(subscriptionPublicKey, eccKeyData.privateKey)

    const publishPublicKeyBuffer = await crypto.subtle.exportKey('raw', eccKeyData.publicKey)

    const auth_secret = base64_to_buffer(base64url_to_base64(auth))

    const key_info = concatBuffer(new TextEncoder('utf-8').encode('WebPush: info\0'), subscriptionPublicKeyBuffer, publishPublicKeyBuffer)

    const PRK_key = await HmacSHA256(auth_secret, ecdh_secret)

    let IKM = await HmacSHA256(PRK_key, concatBuffer(key_info, new Uint8Array([1]).buffer))
    let PRK = await HmacSHA256(salt, IKM)
    let cek_info = new TextEncoder('utf-8').encode('Content-Encoding: aes128gcm\0')
    let contentEncryptionKey = (await HmacSHA256(PRK, concatBuffer(cek_info, new Uint8Array([1]).buffer))).slice(0, 16)
    let nonce_info = new TextEncoder('utf-8').encode('Content-Encoding: nonce\0')
    let nonce = (await HmacSHA256(PRK, concatBuffer(nonce_info, new Uint8Array([1]).buffer))).slice(0, 12)

    return { nonce, cek: contentEncryptionKey, context: key_info }
}

export const Encrypt = async (nonce, contentEncryptionKey, content, encoding = 'aesgcm') => {
    const cek = await crypto.subtle.importKey('raw', contentEncryptionKey, 'AES-GCM', true, ['encrypt', 'decrypt'])
    let payload
    if (encoding === 'aes128gcm') {
        payload = concatBuffer(content, new Uint8Array([2]))
    } else {
        payload = concatBuffer(new Uint8Array([0, 0]), content)
    }
    let encodedBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, cek, payload)
    return encodedBuffer
}
