import kiteFetch from "./FetchApi.js"
import { EventTarget } from 'event-target-shim';
import { parseKiteAppUrl, kiteAppCanonicalUrl } from "./Common.js";
import { generateKiteBoundary, makeFormDataStream } from './FormData.js';

var oldXMLHttpRequest = window.XMLHttpRequest

export default class KiteXMLHttpRequest extends EventTarget {
    constructor (params) {
        super()

        this._xhr = new oldXMLHttpRequest(params)
        this._params = params

        // This gets set to true if our request is a kite request
        this._iskite = false
    }

    set onreadystatechange(hdl) { return this._setKiteHandler('readystatechange', hdl) }
    get onreadystatechange() { return this._getKiteHandler('readystatechange') }
    set ontimeout(hdl) { return this._setKiteHandler('timeout', hdl) }
    get ontimeout() { return this._getKiteHandler('timeout') }

    addEventListener(evtNm, hdl) {
        this._xhr.addEventListener(evtNm, hdl)
        super.addEventListener(evtNm, hdl)
    }

    removeEventListener(evtNm, hdl) {
        this._xhr.removeEventListener('readystatechange', this[evtVarNm])
        super.removeEventListener(evtNm, hdl)
    }

    _setKiteHandler(evtNm, hdl) {
        var evtVarNm = '_on' + evtNm
        if ( this.hasOwnProperty(evtVarNm) ) {
            this.removeEventListener('readystatechange', this[evtVarNm])
        }

        if ( hdl === undefined ) {
            delete this[evtVarNm]
        } else {
            this[evtVarNm] = hdl
            this.addEventListener('readystatechange', hdl)
        }
    }

    _getKiteHandler(evtNm) {
        var evtVarNm = '_on' + evtNm
        return this[evtVarNm]
    }

    _kiteProp(propName, kiteGetter) {
        if ( this._iskite ) {
            if ( kiteGetter === undefined )
                return this['_' + propName]
            else
                return this[kiteGetter]()
        } else
            return this._xhr[propName]
    }

    // Read-only properties
    get readyState() { return this._kiteProp("readyState") }
    get response() { return this._kiteProp("response") }
    get responseText() { return this._kiteProp("responseText") }
    get responseURL() { return this._kiteProp("responseURL") }
    get responseXML() { return this._kiteProp("responseXML") }
    get status() { return this._kiteProp("status") }
    get statusText() { return this._kiteProp("statusText") }
    get upload() { return this._kiteProp("upload") }

    // Read-write properties
    get timeout() { return this._xhr.timeout }
    set timeout(to) { this._xhr.timeout = to }

    get responseType() { return this._xhr.responseType }
    set responseType(rt) { this._xhr.responseType = rt }

    get withCredentials() { return this._xhr.withCredentials }
    set withCredentials(c) { this._xhr.withCredentials = c }

    // Methods

    _callKite(methodName, args) {
        if ( this._iskite ) {
            return this['_' + methodName].apply(this, args)
        } else
            return this._xhr[methodName].apply(this._xhr, args)
    }

    abort() { return this._callKite("abort", arguments) }
    getAllResponseHeaders() { return this._callKite("getAllResponseHeaders", arguments) }
    getResponseHeader() { return this._callKite("getResponseHeader", arguments) }
    overrideMimeType() { return this._callKite("overrideMimeType", arguments) }
    send() { return this._callKite("send", arguments) }
    setRequestHeader() { return this._callKite("setRequestHeader", arguments) }
    sendAsBinary() { return this._callKite("sendAsBinary", arguments) }

    // The open function
    open(method, url, async, user, password) {
        // Check the url
        var kiteUrl = parseKiteAppUrl(url)

        if ( kiteUrl.isKite ) {
            if ( kiteUrl.error )
                throw new TypeError(kiteUrl.error)
            else {
                async = async === undefined ? true : async;

                this._iskite = true

                if ( !async )
                    throw new TypeError("Cannot send synchronous kite requests")

                this._method = method
                this._url = url
                this._response = this._responseText = this._responseURL = ""
                this._responseXML = null
                this._status = 0
                this._statusText = ""
                this._upload = {} // TODO upload
                this._headers = {}
                this._setReadyState(oldXMLHttpRequest.OPENED)
            }
        } else
            this._xhr.open.apply(this._xhr, arguments)
    }

    // Kite-based implementations
    _sendAsBinary() {
        return this._send.apply(this, arguments)
    }

    // Private methods
    _makeTimeoutPromise() {
        if ( this.timeout == 0 )
            return new Promise(() => {})
        else
            return new Promise((resolve, reject) => {
                setTimeout(this.timeout, resolve)
            })
    }

    _setReadyState(rs) {
        this._readyState = rs
        this.dispatchEvent(new Event('readystatechange'))

        if ( rs == oldXMLHttpRequest.DONE ) {
            this.dispatchEvent(new Event('load'))
        }
    }

    _handleTimeout() {
        this._setReadyState(oldXMLHttpRequest.DONE)
        this._sendXHREvent('timeout')
    }

    _handleResponseError(err) {
        this._setReadyState(oldXMLHttpRequest.DONE)
        console.error("Error while attempting kite XMLHttpRequest", err)
        this.dispatchEvent(new ProgressEvent('error', {
                               lengthComputable: false,
                               loaded: 0,
                               total: 0,
                           }))
    }

    _handleResponse(rsp) {
        console.log("Got response", rsp)
        // At this point, all headers are fetched
        this._setReadyState(oldXMLHttpRequest.HEADERS_RECEIVED)

        var decoder = new TextDecoder()
        var sink = {
            start: (controller) => {
            },

            write: (chunk, controller) => {
                console.log("Got chunk", chunk)
                this._responseText += decoder.decode(chunk)
            },

            close: (controller) => {
                this._setReadyState(oldXMLHttpRequest.DONE)
            },

            abort: (reason) => {
                this._setReadyState(oldXMLHttpRequest.DONE)
            }
        };

        console.log("Attempting to consume body", rsp.body)
        this._status = rsp.status
        this._statusText = rsp.statusText
        this._rspHeaders = rsp.headers
        rsp.body.pipeTo(new WritableStream(sink, { highWaterMark: 5 }))
    }

    _setRequestHeader(header, value) {
        this._headers[header] = value
    }


    _makeReadableStream (body) {
        if ( body === undefined || body === null ) {
            return null
        } else if ( body instanceof String || typeof body == 'string' ) {
            throw new TypeError("TODO String")
        } else if ( body instanceof FormData ) {
            var boundary = generateKiteBoundary()
            this.setRequestHeader("Content-Type", boundary.contentType)

            return makeFormDataStream(body, boundary.boundary)
        } else if ( body instanceof URLSearchParams ) {
            throw new TypeError("TODO URLSearchParams")
        } else if ( body instanceof BufferSource ) {
            throw new TypeError("TODO BufferSource")
        } else if ( body instanceof Document ) {
            throw new TypeError("TODO Document")
        }
    }

    _send(body) {
        if ( this._iskite ) {
            var requestInit =
                { method: this._method,
                  headers: this._headers }

            switch ( this._method ) {
            default:
                requestInit.body = this._makeReadableStream(body)
            case 'GET':
            case 'HEAD':
                break;
            }

            var timeout = this._makeTimeoutPromise().then(() => { return { type: 'timeout' } })

            requestInit.kiteOnProgress = (e) => {
                console.log("Got progress event", e)
                this.dispatchEvent(e)
            }

            console.log("Send XHR request", requestInit)
            var fetchPromise = kiteFetch(this._url, requestInit)
                .then((rsp) => { return { type: 'response', rsp: rsp } },
                      (err) => { return { type: 'error', err: err } })

            Promise.race([timeout, fetchPromise])
                .then((res) => {
                    console.log("Raced")
                    switch ( res.type ) {
                    case 'timeout':
                        this._handleTimeout()
                        break
                    case 'response':
                        this._handleResponse(res.rsp)
                        break
                    case 'error':
                        this._handleResponseError(res.err)
                        break
                    default:
                        this._handleResponseError(new TypeError("unknown response type received: " + res.type))
                        break
                    }
                })
        } else {
            return this._xhr.send(body)
        }
    }
}
