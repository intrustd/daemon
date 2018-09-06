import storkFetch from "./FetchApi.js"
import { EventTarget } from 'event-target-shim';
import { parseStorkAppUrl, storkAppCanonicalUrl } from "./Common.js";

var oldXMLHttpRequest = window.XMLHttpRequest

export default class StorkXMLHttpRequest extends EventTarget {
    constructor (params) {
        super()

        this._xhr = new oldXMLHttpRequest(params)
        this._params = params

        // This gets set to true if our request is a stork request
        this._isstork = false
    }

    set onreadystatechange(hdl) { return this._setStorkHandler('readystatechange', hdl) }
    get onreadystatechange() { return this._getStorkHandler('readystatechange') }
    set ontimeout(hdl) { return this._setStorkHandler('timeout', hdl) }
    get ontimeout() { return this._getStorkHandler('timeout') }

    _setStorkHandler(evtNm, hdl) {
        var evtVarNm = '_on' + evtNm
        if ( this.hasOwnProperty(evtVarNm) ) {
            this._xhr.removeEventListener('readystatechange', this[evtVarNm])
            this.removeEventListener('readystatechange', this[evtVarNm])
        }

        if ( hdl === undefined ) {
            delete this[evtVarNm]
        } else {
            this[evtVarNm] = hdl
            this._xhr.addEventListener('readystatechange', hdl)
            this.addEventListener('readystatechange', hdl)
        }
    }

    _getStorkHandler(evtNm) {
        var evtVarNm = '_on' + evtNm
        return this[evtVarNm]
    }

    _storkProp(propName, storkGetter) {
        if ( this._isstork ) {
            if ( storkGetter === undefined )
                return this['_' + propName]
            else
                return this[storkGetter]()
        } else
            return this._xhr[propName]
    }

    // Read-only properties
    get readyState() { return this._storkProp("readyState") }
    get response() { return this._storkProp("response") }
    get responseText() { return this._storkProp("responseText") }
    get responseURL() { return this._storkProp("responseURL") }
    get responseXML() { return this._storkProp("responseXML") }
    get status() { return this._storkProp("status") }
    get statusText() { return this._storkProp("statusText") }
    get upload() { return this._storkProp("upload") }

    // Read-write properties
    get timeout() { return this._xhr.timeout }
    set timeout(to) { this._xhr.timeout = to }

    get responseType() { return this._xhr.responseType }
    set responseType(rt) { this._xhr.responseType = rt }

    get withCredentials() { return this._xhr.withCredentials }
    set withCredentials(c) { this._xhr.withCredentials = c }

    // Methods

    _callStork(methodName, args) {
        if ( this._isstork ) {
            return this['_' + methodName].apply(this, args)
        } else
            return this._xhr[methodName].apply(this._xhr, args)
    }

    abort() { return this._callStork("abort", arguments) }
    getAllResponseHeaders() { return this._callStork("getAllResponseHeaders", arguments) }
    getResponseHeader() { return this._callStork("getResponseHeader", arguments) }
    overrideMimeType() { return this._callStork("overrideMimeType", arguments) }
    send() { return this._callStork("send", arguments) }
    setRequestHeader() { return this._callStork("setRequestHeader", arguments) }
    sendAsBinary() { return this._callStork("sendAsBinary", arguments) }

    // The open function
    open(method, url, async, user, password) {
        // Check the url
        var storkUrl = parseStorkAppUrl(url)

        if ( storkUrl.isStork ) {
            if ( storkUrl.error )
                throw new TypeError(storkUrl.error)
            else {
                async = async === undefined ? true : async;

                this._isstork = true

                if ( !async )
                    throw new TypeError("Cannot send synchronous stork requests")

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

    // Stork-based implementations
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
    }

    _handleTimeout() {
        this._setReadyState(oldXMLHttpRequest.DONE)
        this._sendXHREvent('timeout')
    }

    _handleResponseError(err) {
        this._setReadyState(oldXMLHttpRequest.DONE)
        console.error("Error while attempting stork XMLHttpRequest", err)
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

        console.log("Attempting to consume body")
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
        } else if ( body instanceof USVString ) {
            throw new TypeError("TODO USVString")
        } else if ( body instanceof FormData ) {
            throw new TypeError("TODO FormData")
        } else if ( body instanceof URLSearchParams ) {
            throw new TypeError("TODO URLSearchParams")
        } else if ( body instanceof BufferSource ) {
            throw new TypeError("TODO BufferSource")
        } else if ( body instanceof Document ) {
            throw new TypeError("TODO Document")
        }
    }

    _send(body) {
        if ( this._isstork ) {
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

            var fetchPromise = storkFetch(this._url, requestInit)
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
