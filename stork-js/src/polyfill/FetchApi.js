// An implementation of the fetch API for flock
import { EventTarget } from 'event-target-shim';
import { HTTPParser } from 'http-parser-js';
import { FlockClient } from "../FlockClient.js";
import { ApplianceChooser } from "../ApplianceChooser.js";
import { parseStorkAppUrl, storkAppCanonicalUrl } from "./Common.js";

var oldFetch = window.fetch;

var globalClients = {};

function withLoggedInDevice ( flockUrl ) {
    if ( storkFetch.device === undefined ) {
        var clientPromise;
        if ( globalClients.hasOwnProperty(flockUrl) )
            clientPromise = globalClients[flockUrl];
        else {
            clientPromise = globalClients[flockUrl] =
                new Promise((resolve, reject) => {
                    var client = new FlockClient(flockUrl);

                    var removeEventListeners = () => {
                        client.removeEventListener('open', onOpen);
                        client.removeEventListener('error', onError);
                    }
                    var onOpen = () => {
                        removeEventListeners()
                        resolve(client)
                    }
                    var onError = (e) => {
                        removeEventListeners()
                        reject(e)
                    }

                    client.addEventListener('open', onOpen);
                    client.addEventListener('error', onError);
                }).then((client) => {
                    return new Promise((resolve, reject) => {
                        var deviceChooser = new ApplianceChooser(client);
                        deviceChooser.addEventListener('persona-chosen', (e) => {
                            console.log("Chose person", e);
                            deviceChooser.hide();
                            resolve({client, device: e.device, personaId: e.persona});
                        });
                        deviceChooser.addEventListener('cancel', () => {
                            deviceChooser.hide();
                            reject(new TypeError("The login was canceled by the user"));
                        });
                    });
                }).then(({client, device, personaId}) => {
                    console.log("Going to log in", client, device, personaId)
                    return new Promise((resolve, reject) => {
                        // TODO password?
                        var conn = client.startConnection(device, personaId, [])

                        var removeEventListeners = () => {
                            conn.removeEventListener('open', onOpen);
                            conn.removeEventListener('error', onError);
                        };
                        var onOpen = () => {
                            removeEventListeners();
                            globalClients[flockUrl] = Promise.resolve(conn)
                            resolve(conn);
                        };
                        var onError = () => {
                            removeEventListeners();
                            reject(new TypeError("Could not initiate appliance connection"));
                        };

                        conn.addEventListener('open', onOpen);
                        conn.addEventListener('error', onError);

                        conn.login("") // TODO send some kind of credential (likely a token or something)
                    });
                });
        }

        return clientPromise
    } else
        return Promise.resolve(storkFetch.device);
}

class HTTPResponseEvent {
    constructor (response) {
        this.type = 'response'
        this.response = response
    }
}

class HTTPRequesterError {
    constructor (sts) {
        this.type = 'error'
        this.explanation = sts
    }
}

class HTTPRequester extends EventTarget('response', 'error') {
    constructor(socket, url, req) {
        super()

        this.socket = socket
        this.request = req
        this.url = url

        this.decoder = new TextDecoder()
        this.responseParser = new HTTPParser(HTTPParser.RESPONSE)

        this.response = {
            headers: [],
            status: 500,
            statusText: 'No response'
        };
        this.body = ''

        var addHeaders = (hdrs) => {
            for ( var i = 0; i < hdrs.length; i += 2 ) {
                this.response.headers[hdrs[i]] = hdrs[i + 1]
            }
        }

        this.responseParser[this.responseParser.kOnHeaders] =
            this.responseParser.onHeaders = (hdrs, url) => {
                addHeaders(hdrs)
            }
        this.responseParser[this.responseParser.kOnHeadersComplete] =
            this.responseParser.onHeadersComplete =
            ({versionMajor, versionMinor, headers, statusCode, statusMessage}) => {
                if ( versionMajor == 1 && versionMinor <= 1 ) {
                    addHeaders(headers)
                    this.response.status = statusCode
                    this.response.statusText = statusMessage
                } else
                    this.dispatchEvent(new HTTPRequesterError("Invalid HTTP version " + versionMajor + "." + versionMinor))
            }
        this.responseParser[this.responseParser.kOnBody] =
            this.responseParser.onBody =
            (b, offset, length) => {
                this.body = b.slice(offset, length)

                console.log("Going to provide response", this.body, this.response)
                this.dispatchEvent(new HTTPResponseEvent(new Response(this.body, this.response)))
            }

        this.socket.addEventListener('open', () => {
            var headersToSend = [
                'Host: ' + url.appId,
                'Accept: */*',
                'Accept-Language: ' + navigator.language,
                'Cache-Control: no-cache',
                'Pragma: no-cache',
                'User-Agent: ' + navigator.userAgent
            ];

            var stsLine = this.request.method + ' ' + this.url.path + ' HTTP/1.1\r\n';
            console.log("Sending ", stsLine)

            this.socket.send(stsLine)
            headersToSend.map((hdr) => { this.socket.send(hdr + '\r\n') })
            this.socket.send('\r\n')
            // TODO send body
        })
        this.socket.addEventListener('data', (e) => {
            var dataBuffer = Buffer.from(e.data)
            this.responseParser.execute(dataBuffer)
        })
        this.socket.addEventListener('close', () => {
            this.responseParser.finish()
        })
        this.socket.addEventListener('error', (e) => {
            this.dispatchEvent(e);
        })
    }
}

export default function storkFetch (req, init) {
    var url = req;
    if ( req instanceof Request ) {
        url = req.url;
    }

    var storkUrl = parseStorkAppUrl(url);
    if ( storkUrl.isStork ) {
        if ( storkUrl.hasOwnProperty('error') )
            throw new TypeError(storkUrl.error)
        else {
            console.log("Got stork request", storkUrl);

            if ( req instanceof Request )
                req = new Request(req)
            else
                req = new Request(req, init)

            console.log("Request is ", req)

            var canonAppUrl = storkAppCanonicalUrl(storkUrl);
            return withLoggedInDevice(storkFetch.flockUrl)
                .then((dev) => { return dev.requestApps([ canonAppUrl ])
                                   .then(() => { return dev; }) })
                .then((dev) => {
                    return new Promise((resolve, reject) => {
                        var socket = dev.socketTCP(canonAppUrl, storkUrl.port);
                        var httpRequestor = new HTTPRequester(socket, storkUrl, req)
                        httpRequestor.addEventListener('response', (resp) => {
                            resolve(resp.response)
                        })
                        httpRequestor.addEventListener('error', (e) => {
                            reject(new TypeError(e.explanation))
                        })
                    })
                });
        }
    } else
        return oldFetch.apply(this, arguments);
}

// TODO allow people to update this URL
storkFetch.flockUrl = "ws://localhost:6854/";
