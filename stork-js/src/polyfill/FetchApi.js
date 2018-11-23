// An implementation of the fetch API for flock
import { EventTarget } from 'event-target-shim';
import { HTTPParser } from 'http-parser-js';
import { FlockClient } from "../FlockClient.js";
import { Authenticator } from "../Authenticator.js";
import { PortalAuthenticator } from "../Portal.js";
import { parseKiteAppUrl, kiteAppCanonicalUrl } from "./Common.js";
import { generateKiteBonudary, makeFormDataStream } from "./FormData.js";
import { BlobReader } from "./Streams.js";
import { CacheControl } from "./Cache.js";
import { getSite, resetSite } from "../Site.js";
import ProgressManager from "./Progress.js";

var oldFetch = window.fetch;

var globalFlocks = {};
var globalAppliance;

if ( !window.ReadableStream ) {
    var streamsPolyfill = require('web-streams-polyfill')
    window.ReadableStream = streamsPolyfill.ReadableStream;
}

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
            console.log("Going to send headers", this.request.headers)
            var headers = new Headers(this.request.headers)
            headers.append('Host', url.app)
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
                console.log("Sending body")
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
            console.log("Got response", dataBuffer)
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

var globalClient;

function chooseNewAppliance(flocks, site) {
    if ( kiteFetch.require_login ) {
        return new Promise((resolve, reject) => {
            var chooser = new Authenticator(flocks, site)
            chooser.addEventListener('error', (e) => {
                globalClient = undefined;
                reject(e);
            });

            chooser.addEventListener('open', (e) => {
                // TODO request permissions from admin app
                resolve(e.device)
            });
        })
    } else {
        // The best way to log in is to use the flock recommended
        // portal app. Ask the flock which application is best
        return new Promise((resolve, reject) => {
            var chooser = new PortalAuthenticator(flocks, site, oldFetch, kiteFetch.permissions)

            chooser.addEventListener('error', (e) => {
                globalClient = undefined;
                reject(e);
            })

            chooser.addEventListener('open', (e) => {
                resolve(e.device)
            })
        })
    }
}

function getGlobalClient(flocks, site) {
    if ( globalClient === undefined ) {
        if ( site !== undefined &&
             site !== null ) {
            globalClient = loginToSite(site)
                .catch((e) => { resetSite(); return chooseNewAppliance(flocks, site) })
        } else {
            globalClient = chooseNewAppliance(flocks, site)
        }
    }
    return globalClient;
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
            var canonAppUrl = kiteUrl.app;
            var clientPromise

            if ( req instanceof Request )
                req = new Request(req)
            else {
                req = new Request(req, init)

                if ( init.hasOwnProperty('body') )
                    req.body = init.body
            }

            if ( kiteFetch.rewrite.hasOwnProperty(canonAppUrl) ) {
                var newUrl = kiteFetch.rewrite[canonAppUrl].replace(/\[path\]/g, kiteUrl.path)

                console.log("Rewrite to ", newUrl)

                req = new Request(newUrl, { method: req.method,
                                            body: req.body,
                                            mode: req.mode,
                                            credentials: req.credentials,
                                            cache: req.cache,
                                            redirect: req.redirect,
                                            referrer: req.referrer,
                                            integrity: req.integrity })
                return oldFetch.apply(this, [ req ])
            }

            if ( init.hasOwnProperty('kiteClient') )
                clientPromise = Promise.resolve(init['kiteClient'])
            else
                clientPromise = getGlobalClient(flockUrls, getSite())

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
                            if ( req.cache != 'no-store' ) {
                                var cache = new Promise((resolve, reject) => {
                                    if ( dev._kiteCache === undefined ) {
                                        dev._kiteCache = new CacheControl(dev.flockUrl,
                                                                          dev.appliance,
                                                                          dev.personaId,
                                                                          canonAppUrl)
                                        resolve(dev._kiteCache)
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
                            } else {
                                tracker.done()
                                resolve(resp.response)
                            }
                        })
                        httpRequestor.addEventListener('error', (e) => {
                            reject(new TypeError(e.explanation))
                        })
                    }))
            }

            return clientPromise
                .then((dev) => {
                    if ( req.cache == 'no-store' ||
                         req.cache == 'reload' ) {
                        return runRequest(dev)
                    } else {
                        if ( dev._kiteCache ) {
                            return dev._kiteCache.matchRequest(req)
                                .then((rsp) => {
                                    if ( rsp === undefined )
                                        return runRequest(dev)
                                    else {
                                        return rsp
                                    }
                                })
                        } else {
                            return runRequest(dev)
                        }
                    }
                })
        }
    } else
        return oldFetch.apply(this, arguments);
}

kiteFetch.flockUrls = [
    { url: "localhost:6855",
      secure: false,
      path: '/flock/' },
    { url: "flock.flywithkite.com",
      path: "/flock/",
      secure: true }
]
