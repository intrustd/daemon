// An implementation of the fetch API for flock
import { EventTarget } from 'event-target-shim';
import { HTTPParser } from 'http-parser-js';
import { FlockClient } from "../FlockClient.js";
import { ApplianceChooser, PersonaChooser } from "../ApplianceChooser.js";
import { parseKiteAppUrl, kiteAppCanonicalUrl } from "./Common.js";
import { generateKiteBonudary, makeFormDataStream } from "./FormData.js";
import { BlobReader } from "./Streams.js";
import { CacheControl } from "./Cache.js";
import ProgressManager from "./Progress.js";

var oldFetch = window.fetch;

var globalFlocks = {};
var globalAppliance;

if ( !window.ReadableStream ) {
    var streamsPolyfill = require('web-streams-polyfill')
    window.ReadableStream = streamsPolyfill.ReadableStream;
}

class GlobalAppliance {
    constructor ( flock, applianceName, defClient ) {
        this.flock = flock;
        this.applianceName = applianceName;
        this.defaultPersona = defClient;
        this.personas = {};
    }

    markDefault() {
        return this.flock.setDefaultAppliance(this.applianceName)
    }

    getPersonaClient(persona) {
        if ( this.personas.hasOwnProperty(persona) )
            return Promise.resolve(this.personas[persona]);
        else {
            console.error("TODO getPersonaClient");
        }
    }

    getDefaultPersonaClient() {
        if ( this.defaultPersona.isLoggedIn() ) {
            return Promise.resolve(this.defaultPersona);
        } else {
            return new Promise((resolve, reject) => {
                var chooser = new PersonaChooser (this.defaultPersona);
                chooser.addEventListener('persona-chosen', ({personaId, creds}) => {
                    this.defaultPersona.tryLogin(personaId, creds)
                        .then(() => { chooser.hide(); resolve(this.defaultPersona); },
                              () => { chooser.showError(); })
                });
                chooser.addEventListener('cancel', () => { reject('canceled'); });
            });
        }
    }
}

class GlobalFlock {
    constructor ( flockUrl ) {
        this.flockUrl = flockUrl;
        this.defaultAppliance = null;
        this.appliances = {};
    }

    setDefaultAppliance(applianceName) {
        return this.getAppliance(applianceName)
            .then((app) => {
                console.log("Setting default appliance", app)
                this.defaultAppliance = app;
                return app
            })
    }

    getAppliance(applianceName) {
        // Attempt connect to this appliance
        if ( this.appliances.hasOwnProperty(applianceName) ) {
            return Promise.resolve(this.appliances[applianceName]);
        } else {
            return new Promise((resolve, reject) => {
                console.log("Get appliance", applianceName)
                var client = new FlockClient({ url: this.flockUrl,
                                               appliance: applianceName });
                var removeEventListeners = () => {
                    client.removeEventListener('open', onOpen);
                    client.removeEventListener('error', onError);
                }
                var onOpen = () => {
                    console.log("Appliance", applianceName, " opens")
                    removeEventListeners();
                    this.appliances[applianceName] =
                        new GlobalAppliance(this, applianceName, client);
                    resolve(this.appliances[applianceName]);
                };
                var onError = (e) => {
                    removeEventListeners();
                    reject(e);
                }
                client.addEventListener('open', onOpen);
                client.addEventListener('error', onError);
            });
        }
    }

    getDefaultAppliance(options) {
        if (options === undefined) options = {}

        if ( this.defaultAppliance )
            return Promise.resolve(this.defaultAppliance);
        else {
            if ( options.silent ) return Promise.reject()
            else {
                return new Promise((resolve, reject) => {
                    var chooser = new ApplianceChooser(this.flockUrl);
                    chooser.addEventListener('appliance-chosen', (e) => {
                        this.getAppliance(e.device).then(
                            (devClient) => {
                                chooser.hide();
                                resolve(devClient)
                                this.defaultAppliance = devClient
                            },
                            (e) => { console.error(e); chooser.signalError() }
                        );
                    });
                    chooser.addEventListener('cancel', () => reject('canceled'));
                });
            }
        }
    }
};

// function withLoggedInDevice ( flockUrl ) {
//     if ( kiteFetch.device === undefined ) {
//         var clientPromise;
//         if ( globalClients.hasOwnProperty(flockUrl) )
//             clientPromise = globalClients[flockUrl];
//         else {
//             clientPromise = globalClients[flockUrl] =
//                 new Promise((resolve, reject) => {
//                     var client = new FlockClient(flockUrl);
// 
//                     var removeEventListeners = () => {
//                         client.removeEventListener('open', onOpen);
//                         client.removeEventListener('error', onError);
//                     }
//                     var onOpen = () => {
//                         removeEventListeners()
//                         resolve(client)
//                     }
//                     var onError = (e) => {
//                         removeEventListeners()
//                         reject(e)
//                     }
// 
//                     client.addEventListener('open', onOpen);
//                     client.addEventListener('error', onError);
//                 }).then((client) => {
//                     return new Promise((resolve, reject) => {
//                         var deviceChooser = new ApplianceChooser(client);
//                         deviceChooser.addEventListener('persona-chosen', (e) => {
//                             console.log("Chose person", e);
//                             deviceChooser.hide();
//                             resolve({client, device: e.device, personaId: e.persona});
//                         });
//                         deviceChooser.addEventListener('cancel', () => {
//                             deviceChooser.hide();
//                             reject(new TypeError("The login was canceled by the user"));
//                         });
//                     });
//                 }).then(({client, device, personaId}) => {
//                     console.log("Going to log in", client, device, personaId)
//                     return new Promise((resolve, reject) => {
//                         // TODO password?
//                         var conn = client.startConnection(device, personaId, [])
// 
//                         var removeEventListeners = () => {
//                             conn.removeEventListener('open', onOpen);
//                             conn.removeEventListener('error', onError);
//                         };
//                         var onOpen = () => {
//                             removeEventListeners();
//                             globalClients[flockUrl] = Promise.resolve(conn)
//                             resolve(conn);
//                         };
//                         var onError = () => {
//                             removeEventListeners();
//                             reject(new TypeError("Could not initiate appliance connection"));
//                         };
// 
//                         conn.addEventListener('open', onOpen);
//                         conn.addEventListener('error', onError);
// 
//                         conn.login("") // TODO send some kind of credential (likely a token or something)
//                     });
//                 });
//         }
// 
//         return clientPromise
//     } else
//         return Promise.resolve(kiteFetch.device);
// }

class HTTPResponseEvent {
    constructor (response, responseBlob) {
        this.type = 'response'
        this.response = response
        this.responseBlob = responseBlob
    }
}

class HTTPPartialLoadEvent {
    constructor (requestor, loaded) {
        this.type = 'partialload'
        this.request = requestor
        this.loaded = loaded
        this.total = requestor.responseContentLength
    }
}

class HTTPRequesterError {
    constructor (sts) {
        this.type = 'error'
        this.explanation = sts
    }
}

class HTTPRequester extends EventTarget('response', 'error', 'progress') {
    constructor(socket, url, req) {
        super()

        this.socket = socket
        this.request = req
        this.url = url

        this.decoder = new TextDecoder()
        this.responseParser = new HTTPParser(HTTPParser.RESPONSE)

        this.response = {
            credentials: 'same-origin',
            mode: 'no-cors',
            headers: new Headers(),
            status: 500,
            statusText: 'No response'
        };
        this.body = []

        var addHeaders = (hdrs) => {
            console.log("Adding headers", hdrs)
            for ( var i = 0; i < hdrs.length; i += 2 ) {
                this.response.headers.set(hdrs[i], hdrs[i + 1])
            }

            var contentLength = this.response.headers.get('content-length')
            if ( contentLength !== null ) {
                this.responseContentLength = parseInt(contentLength)
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
                } else {
                    this.dispatchEvent(new HTTPRequesterError("Invalid HTTP version " + versionMajor + "." + versionMinor))
                    this.cleanupSocket()
                }
            }
        var totalBody = 0;
        var frameRequested = null;
        this.responseParser[this.responseParser.kOnBody] =
            this.responseParser.onBody =
            (b, offset, length) => {
                var sliced = b.slice(offset, offset + length)
                totalBody += length
//                if ( !noted ) {
//                    noted = true;
//                    console.log("Started", totalBody, "for", this.url.path)
//                } else
//                    console.log("Body", totalBody, "for", this.url.path)
//                console.log("Got body", sliced, totalBody)
//                window.currentKiteReq = this
//                console.log("Got body ", b, offset, length)
                this.body.push(sliced)
                if ( frameRequested === null ) {
                    frameRequested = window.requestAnimationFrame(() => { this.sendPartialLoadEvent(totalBody); frameRequested = null })
                }
            }

        var onComplete =
            this.responseParser[this.responseParser.kOnMessageComplete] =
            this.responseParser.onMessageComplete =
            () => {
                console.log("Going to provide response", this.body, this.response)
                this.response.headers.set('access-control-allow-origin', '*')
                for (var pair of this.response.headers.entries()) {
                    console.log(pair[0]+ ': '+ pair[1]);
                }
                //                this.responsethis.response.headers.map((hdr) => { console.log("Got header", hdr) })

                var responseBlob = this.currentBody
                if ( frameRequested !== null )
                    window.cancelAnimationFrame(frameRequested)
                this.sendPartialLoadEvent(totalBody)
                this.dispatchEvent(new HTTPResponseEvent(new Response(responseBlob, this.response),
                                                         responseBlob))
                this.cleanupSocket()
            }

        this.socket.addEventListener('open', () => {
            var headers = new Headers(this.request.headers)
            headers.append('Host', url.appId)
            headers.append('Accept', '*/*')
            headers.append('Accept-Language', navigator.language)
            headers.append('Cache-Control', 'no-cache')
            headers.append('Pragma', 'no-cache')
            headers.append('User-Agent', navigator.userAgent)

            var stsLine = this.request.method + ' ' + this.url.path + ' HTTP/1.1\r\n';
            var bodyLengthCalculated = Promise.resolve()
            console.log("Sending ", stsLine)

            this.socket.send(stsLine)
            var doSendBody = () => {
                this.sendProgressEvent(50, 50)
            }
            var continueSend = () => {
                for ( var header of headers ) {
                    var hdrLn = `${header[0]}: ${header[1]}\r\n`
                    console.log("Header", hdrLn)
                    this.socket.send(hdrLn)
                }
                this.socket.send('\r\n')
                doSendBody()
            }

            console.log("Fetching", this.request, this.request.hasOwnProperty('body'))
            if ( this.request.hasOwnProperty('body') ) {
                bodyLengthCalculated =
                    this.calculateBodyLength(this.request.body)
                    .then(({length, bodyStream, contentType}) => {
                        this.sendProgressEvent(0, length)
                        this.bodyLength = length

                        headers.set('Content-Length', length + '')
                        if ( contentType !== undefined && contentType !== null &&
                             !headers.has('Content-type') ) {
                            headers.set('Content-type', contentType)
                        }
                        doSendBody = () => { this.sendBody(bodyStream) }
                    })
                    .catch((e) => {
                        console.error("could not calculate length", e)
                        this.dispatchEvent(new HTTPRequesterError("Could not calculate body length: " + e))
                        this.cleanupSocket()
                    })
            } else
                this.sendProgressEvent(0, 50)

            bodyLengthCalculated
                .then(() => {
                    continueSend()
                })
        })
        this.socket.addEventListener('data', (e) => {
            var dataBuffer = Buffer.from(e.data)
            //console.log("Got response", dataBuffer)
            this.responseParser.execute(dataBuffer)
        })
        this.socket.addEventListener('close', () => {
            this.responseParser.finish()
        })
        this.socket.addEventListener('error', (e) => {
            this.dispatchEvent(e);
        })
    }

    sendBody(bodyStream) {
        this.socket.sendStream(bodyStream, (sent) => {
            console.log("Sending", sent)
            this.sendProgressEvent(sent, this.bodyLength)
        })
    }

    get currentBody() {
        var blobProps = { type: this.response.headers.get('content-type') }
        console.log("Got blob props", blobProps)
        return new Blob(this.body, blobProps)
    }

    sendPartialLoadEvent(loaded) {
        this.dispatchEvent(new HTTPPartialLoadEvent(this, loaded))
    }

    sendProgressEvent(length, total) {
        this.dispatchEvent(new ProgressEvent('progress', { lengthComputable: true,
                                                           loaded: length, total: total }))
    }

    cleanupSocket() {
        console.log("Cleanup socket")
        this.socket.close()
        delete this.socket
    }

    calculateBodyLength(body) {
        if ( body instanceof ReadableStream ) {
            return this.calculateBodyLengthStream(body)
        } else if ( body instanceof Blob ) {
            return { length: body.length,
                     bodyStream: BlobReader(body) }
        } else if ( body instanceof String || typeof body == 'string' ) {
            var blob = new Blob([body])
            return Promise.resolve({ length: body.length,
                                     bodyStream: BlobReader(blob) })
        } else if ( body instanceof FormData ) {
            var boundary = generateKiteBoundary()
            return this.calculateBodyLengthStream(makeFormDataStream(body, boundary.boundary))
                .then((o) => { o.contentType = boundary.contentType; return o })
        } else if ( body instanceof BufferSource ) {
            return Promise.reject(new TypeError("TODO BufferSource send"))
        } else if ( body instanceof URLSearchParams ) {
            return Promise.reject(new TypeError("TODO URLSearchParams send"))
        } else {
            return Promise.reject(new TypeError("Invalid type for 'body'"))
        }
    }

    calculateBodyLengthStream(body) {
        var bodies = body.tee()
        var lengthBody = bodies[0]
        var bodySource = bodies[1]

        return new Promise((resolve, reject) => {
            var lengthReader = lengthBody.getReader()
            var totalLength = 0
            var doCalc = () => {
                lengthReader.read().then(({done, value}) => {
                    if ( done ) {
                        console.log('totalLength', totalLength)
                        resolve({ length: totalLength, bodyStream: bodySource })
                    } else {
                        console.log('totalLength adding', totalLength, value.byteLength, value)
                        if ( value instanceof ArrayBuffer )
                            totalLength += value.byteLength
                        else if ( typeof value == 'string' )
                            totalLength += value.length
                        else {
                            console.error("Can't get length of ", value)
                            throw new TypeError("Don't know how to get length of " + value)
                        }
                        doCalc()
                    }
                })
            }
            doCalc()
        })
    }
}

export default function kiteFetch (req, init) {
    var url = req;
    if ( req instanceof Request ) {
        url = req.url;
    }

    var kiteUrl = parseKiteAppUrl(url);
    if ( kiteUrl.isKite ) {
        if ( kiteUrl.hasOwnProperty('error') )
            throw new TypeError(kiteUrl.error)
        else {
            var flockUrls = kiteFetch.flockUrls;
            var canonAppUrl = kiteAppCanonicalUrl(kiteUrl);
            var appliancePromise, clientPromise;

            console.log("Got kite request", kiteUrl);

            if ( init.hasOwnProperty('flockUrls') ) {
                flockUrls = init.flockUrls;
                delete init.flockUrls;
            }

            else if ( init.hasOwnProperty('flockUrl') ) {
                flockUrls = [ init.flockUrl ];
                delete init.flockUrl;
            }

            if ( flockUrls.length == 0 )
                throw new TypeError("Expected at least one flock URL");

            console.log("Attempting connection with ", flockUrls)
            for ( var flockUrl of flockUrls.values() ) {
                if ( !globalFlocks.hasOwnProperty(flockUrl) ) {
                    globalFlocks[flockUrl] = new GlobalFlock(flockUrl);
                }
            }
            console.log("Got flock ", globalFlocks)

            var applianceByName =
                (applianceName) => {
                    var applianceFromFlock = (flock) => {
                        if ( applianceName === undefined )
                            return flock.getDefaultAppliance({silent: true})
                        else
                            return flock.getAppliance(applianceName)
                    }

                    var getAppliances = flockUrls.map((flockUrl, i) => {
                        return () => {
                            return applianceFromFlock(globalFlocks[flockUrl])
                                .then((dev) => { console.log("Got appliance success", dev, flockUrl); return dev; })
                                .catch((e) => {
                                    if ( (i + 1) >= getAppliances.length )
                                        return Promise.reject(e)
                                    else
                                        return getAppliances[i + 1]()
                                })
                        }
                    })

                    return getAppliances[0]()
                }

            if ( init.hasOwnProperty('applianceName') ) {
                appliancePromise = applianceByName(init.applianceName)
                delete init.applianceName
            } else {
                var appliancePromise =
                    // Check if any global flock has a default appliance
                    applianceByName()
                    .catch(() => {
                        return new Promise((resolve, reject) => {
                            var chooser = new ApplianceChooser(flockUrls)
                            chooser.addEventListener('appliance-chosen', (e) => {
                                applianceByName(e.device).then(
                                    (devClient) => {
                                        chooser.hide()
                                    devClient.markDefault()
                                            .then(() => { resolve(devClient) })
                                    },
                                    (e) => {
                                        console.error(e)
                                        chooser.signalError(e)
                                })
                            })
                        chooser.addEventListener('cancel', () => reject('canceled'))
                        })
                    })
            }

            if ( init.hasOwnProperty('persona') ) {
                var persona = init.persona;
                clientPromise = appliancePromise.then((appliance) => appliance.getPersonaClient(persona));
                delete init.persona;
            } else {
                clientPromise = appliancePromise.then((appliance) => appliance.getDefaultPersonaClient());
            }

            if ( req instanceof Request )
                req = new Request(req)
            else {
                req = new Request(req, init)

                if ( init.hasOwnProperty('body') )
                    req.body = init.body
            }

            console.log("Request is ", req, init)

            var runRequest = (dev) => {
                var tracker = ProgressManager.startFetch()

                return dev.requestApps([ canonAppUrl ])
                    .then(() => dev)
                    .then((dev) => new Promise((resolve, reject) => {
                        var socket = dev.socketTCP(canonAppUrl, kiteUrl.port);
                        var httpRequestor = new HTTPRequester(socket, kiteUrl, req)
                        var requestTracker = tracker.subtracker(50, 100)

                        if ( init.kiteOnProgress ) {
                            httpRequestor.addEventListener('progress', init.kiteOnProgress)
                        }
                        httpRequestor.addEventListener('progress', (p) => {
                            if ( p.lengthComputable ) {
                                requestTracker.setProgress(p.loaded, p.total)
                            }
                        })

                        if ( init.kiteOnPartialLoad ) {
                            httpRequestor.addEventListener('partialload', init.kiteOnPartialLoad)
                        }
                        httpRequestor.addEventListener('partialload', (pl) => {
                            if ( pl.total ) {
                                tracker.setProgress(pl.loaded, pl.total)
                            }
                        })

                        httpRequestor.addEventListener('response', (resp) => {
                            var cache = new Promise((resolve, reject) => {
                                if ( dev._kiteCache === undefined ) {
                                    appliancePromise.then((app) => {
                                        var flock = app.flock
                                        dev._kiteCache = new CacheControl(flock.flockUrl,
                                                                          app.applianceName,
                                                                          dev.personaId,
                                                                          canonAppUrl)
                                        resolve(dev._kiteCache)
                                    })
                                } else
                                    resolve(dev._kiteCache)
                            })

                            cache.then((cache) => {
                                console.log("Got response", resp.response);
                                var responseInit = { status: resp.response.status,
                                                     statusText: resp.response.statusText,
                                                     headers: resp.response.headers };

                                cache.cacheResponse(req, responseInit, resp.responseBlob)
                                    .then(() => {
                                        tracker.done()
                                        resolve(resp.response)
                                    })
                                    .catch(() => { tracker.done() })
                            }).catch((e) => { console.error("Error while caching", e) })
                        })
                        httpRequestor.addEventListener('error', (e) => {
                            reject(new TypeError(e.explanation))
                        })
                    }))
            }

            return clientPromise
                .then((dev) => {
                    if ( dev._kiteCache ) {
                        return dev._kiteCache.matchRequest(req)
                            .then((rsp) => {
                                if ( rsp === undefined )
                                    return runRequest(dev)
                                else
                                    return rsp
                            })
                    } else {
                        return runRequest(dev)
                    }
                })
        }
    } else
        return oldFetch.apply(this, arguments);
}

// TODO allow people to update this URL
kiteFetch.flockUrls = [
    "ws://localhost:6853/",
    "ws://34.221.26.224:6853/"
]
