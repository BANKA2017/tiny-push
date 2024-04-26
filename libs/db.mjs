import { writeFile } from 'fs'
import log from './console.mjs'

export const saveKV = async (path = './db/kv.json', kv = {}) => {
    //log.log(path, JSON.stringify(kv))
    return writeFile(path, JSON.stringify(kv), (callback) => {
        if (callback) {
            log.error(callback)
        }
    })
}
