# push

## init

-   Create a file in `/db/` named `kv.json` and fill by text `{}`
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

## then?

```shell
node app.mjs

# bun run app.mjs
```
