export const GetUUID = async (handle, uuid = '') =>
    new Promise((resolve) => {
        handle.get('SELECT * FROM channel WHERE uuid = ?;', uuid, (err, row) => {
            resolve({ err, row })
        })
    })

export const InsertUUID = async (handle, data = []) =>
    new Promise((resolve) => {
        handle.run('INSERT INTO channel (uuid, endpoint, auth, p256dh, last_used) VALUES (?, ?, ?, ?, ?);', data, (err) => {
            resolve(err)
        })
    })

const variableMap = {
    $uuid: 'uuid',
    $endpoint: 'endpoint',
    $auth: 'auth',
    $p256dh: 'p256dh',
    $target: 'target',
    $last_used: 'last_used',
    $count: 'count'
}

export const UpdateUUID = async (handle, data = {}) =>
    new Promise((resolve) => {
        const setContent = Object.keys(data)
            .map((key) => {
                if (variableMap[key] && key !== '$uuid') {
                    return `${variableMap[key]} = ${key}`
                }
                return ''
            })
            .filter((data) => data)
            .join(', ')

        handle.run('UPDATE channel SET ' + setContent + ' WHERE uuid = $uuid;', data, (err) => {
            resolve(err)
        })
    })

export const DeleteUUID = async (handle, uuid = '') =>
    new Promise((resolve) => {
        handle.run('DELETE FROM channel WHERE uuid = ?;', uuid, (err) => {
            resolve(err)
        })
    })
