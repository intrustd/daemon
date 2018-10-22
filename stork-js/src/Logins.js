import Dexie from 'dexie';
import { Record, Map, List } from 'immutable';

import { FlockClient } from './FlockClient.js';

var loginsDb

const LoginKey = Record({ flock: '',
                          appliance: '',
                          persona: '' })

export class Login {
    constructor(data, siteCertificate, now) {
        this.personaId = data.persona_id
        this.flockUrl = data.flock
        this.applianceName = data.appliance
        this.loginToken = data.token
        this.expiration = data.exp
        this.siteCertificate = siteCertificate

        if ( now === undefined )
            now = Date.now()

        this.now = now
    }

    get key() {
        return LoginKey({ flock: this.flockUrl,
                          appliance: this.applianceName,
                          persona: this.personaId })
    }

    get isExpired() {
        return this.expiration <= this.now
    }

    createClient() {
        return new Promise((resolve, reject) => {
            var client = new FlockClient({ url: this.flockUrl,
                                           appliance: this.applianceName })
            client.addEventListener('error', reject)
            client.addEventListener('open', () => {
                var persona = this.personaId
                if ( persona === undefined )
                    persona = 'token'
                client.tryLogin(persona, `token:${this.loginToken}`)
                    .then(() => resolve(client))
                    .catch((e) => {
                        console.error("Could not login to client", e)
                        reject(e)
                    })
            })

        })
    }

    save() {
        var loginData = { persona_id: this.personaId,
                          flock: this.flockUrl,
                          appliance: this.applianceName,
                          token: this.loginToken,
                          exp: this.expiration }
        console.log("Saving", loginData)
        return getLoginsDb()
            .then((db) => db.login.put(loginData))
            .then((key) => console.log("Got key", key))
    }
}

export function getLoginsDb() {
    if ( loginsDb === undefined )
        loginsDb = new Promise((resolve, reject) => {
            var db = new Dexie('kite-logins');
            db.version(8).stores({
                login: 'token,exp,[persona_id+flock+appliance]',
                site: 'exp'
            })
            db.version(7).stores({
                logins: 'token,exp,[persona_id+flock+appliance]',
                site: 'exp'
            })
            db.version(6).stores({
                logins: '[exp+token],[persona_id+flock+appliance+exp]',
                site: 'exp'
            })
            db.version(5).stores({
                logins: '[persona_id+flock+appliance+exp], token',
                site: 'exp'
            })
            db.version(4).stores({
                logins: '[persona_id+flock+appliance+exp]',
                site: 'exp'
            })
            db.version(3).stores({
                logins: 'persona_id, [flock+appliance], exp',
                site: 'exp'
            })
            db.version(2).stores({
                logins: 'persona_id, [flock+appliance]',
                site: 'exp'
            })
            db.version(1).stores({
                logins: 'persona_id, [flock+appliance]'
            })

            resolve(db.open())
        })

    return loginsDb
}

export function getSite(db) {
    var now = Date.now()
    return db.site.where('exp').above(now).toArray()
        .then((sites) => {
            if ( sites.length == 0 ) {
                return Promise.all(
                    [RTCPeerConnection.generateCertificate({ name: 'ECDSA', namedCurve: 'P-256' }),
                     db.site.where('exp').belowOrEqual(now).delete()])
                    .then(([cert, done]) => db.site.add({exp: cert.expires, cert}).then(() => cert))
            } else {
                return sites[0].cert
            }
        });
}

export function lookupLogins() {
    var now = Date.now()
    return getLoginsDb()
        .then((db) => {
            return Promise.all([getSite(db), db.login.where('exp').above(now).toArray()])
        }).then(([site, logins]) => {
            console.log("Got logins", logins)
            logins = List(logins)
                .map((login) => new Login(login, site, now))
                .groupBy((login) => login.key)

            console.log("After group ", JSON.stringify(logins))

            logins = logins
                .map((loginOptions) => loginOptions.maxBy((login) => login.expiration))
                .valueSeq().toArray()

            console.log("Got all logins", logins, site, logins.length, site.getFingerprints()[0].value);
            return logins
        }).catch((e) => { console.error("Error while running dexie", e)})
}

window.getLogins = getLoginsDb;
window.lookupLogins = lookupLogins;
