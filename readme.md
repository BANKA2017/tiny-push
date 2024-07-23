# TinyPush

## init

-   Create a file in `/db/` named `tinypush.db` by file `tinypush.sql`
-   Create a file in `/db/` named `vapid.mjs`

    ```javascript
    // ./db/vapid.mjs
    export const VAPID = {
        key: { crv: 'P-256', d: '990qYS0DMoxen3c6VoFzl5HvOj29z6hyK5MM3iXTmdM', ext: true, key_ops: ['sign'], kty: 'EC', x: 'x_NazY4_xbONkZEVKm_sn-X9v2oKZ2uUB_cqQQjk9ns', y: 'jMl88osu-s38mB5S1__qTWRDAJ3okLtTPBcSyLxc33U' },
        sub: 'mailto:your@example.com'
    }
    ```

    -   `key`: jwk of the private key

        ```javascript
        JSON.stringify(await crypto.subtle.exportKey('jwk', (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])).privateKey))
        ```

    -   `sub`: your email

-   Default port is `3002`, use env `TINYPUSH_PORT`
-   replace `push.nest.moe` with your own domain <- self deploy

## then?

```shell
node app.mjs

# bun run app.mjs
```

## more...

-   `uuid` will expire 90 days after last use
-   It is not necessary to use `uuid` when providing `endpoint`, `p256dh` and `auth` directly

## API

-   `GET` /api/vapid
    -   method: `GET`
    -   response:
        ```json
        {
            "code": 200,
            "message": "OK",
            "data": {
                "vapid": "<string>"
            },
            "version": "push"
        }
        ```
-   `POST` /api/subscribe/
    -   method: `POST`
    -   Content-Type: `application/x-www-form-urlencoded`
    -   body:
        -   endpoint: `<string>`
        -   p256dh: `<string>`
        -   auth: `<string>`
    -   response:
        ```json
        // success
        {
            "code": 200,
            "message": "OK",
            "data": {
                "uuid": "<string>"
            },
            "version": "push"
        }
        // failed
        /// `uuid` here is unused
        { "code": 401, "message": "Invalid p256dh/auth/endpoint", "data": { "uuid": "<string>" }, "version": "push" }
        { "code": 401, "message": "Invalid endpoint", "data": { "uuid": "<string>" }, "version": "push" }
        { "code": 500, "message": "Failed to generate uuid", "data": { "uuid": "<string>" }, "version": "push" }
        ```
-   `DELETE` /api/subscribe/:uuid
    -   method: `DELETE`
    -   Content-Type: `application/x-www-form-urlencoded`
    -   response:
        ```json
        { "code": 200, "message": "OK", "data": true, "version": "push" }
        ```
-   `POST` /api/push/:uuid?

    -   method: `POST`
    -   Content-Type: `application/x-www-form-urlencoded`
    -   body:
        -   endpoint?: `<string>`
        -   p256dh?: `<string>`
        -   auth?: `<string>`
        -   test?: `1` || `undefined`
        -   encoding?: `aes128gcm` || `aesgcm`
        -   message: `<string>`
    -   response:

        ```json
        /// code === data.status

        // success
        {
            "code": 201,
            "message": "OK",
            "data": {
                "status": 201,
                "text": "<string>"
            },
            "version": "push"
        }
        // failed
        /// `code !== 201`


        /// https://web.dev/articles/push-notifications-common-issues-and-reporting-bugs
        ```

    -   ext:
        -   `endpoint/p256dh/auth` > `uuid`
        -   when `test=1`, `message` in body can be empty, we will push a test message:
            ```plaintext
            This is a test content🔔✅🎉😺
            Fri Apr 26 2024 10:36:06 GMT+0800 (China Standard Time) (1714098966547)
            ```
