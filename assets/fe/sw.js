self.addEventListener('install', () => {
    self.skipWaiting()
})

self.addEventListener('push', (event) => {
    const message = event.data?.json() || {}
    if (message) {
        self.registration.showNotification('TinyPush', {
            body: message?.content || '',
            icon: '/icon_small.png',
            badge: '/icon_small.png',
            data: message,
            timestamp: message.timestamp,
            tag: 'message-' + message.timestamp
        })
    }
})

self.addEventListener(
    'notificationclick',
    function (event) {
        event.notification.close()
        const { content, sign, timestamp } = event.notification.data
        let binary = ''
        const bytes = new TextEncoder('utf-8').encode(content)
        for (var i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i])
        }

        clients.openWindow(
            '/#/preview/' +
                btoa(JSON.stringify({ content: btoa(binary).replaceAll('/', '_').replaceAll('+', '-').replaceAll('=', ''), sign, timestamp }))
                    .replaceAll('/', '_')
                    .replaceAll('+', '-')
                    .replaceAll('=', '')
        )
    },
    false
)
