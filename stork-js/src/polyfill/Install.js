import kiteFetch from './FetchApi.js'
import kiteXMLHttpRequest from './XhrApi.js'

export default function (options) {
    console.log("Installing Kite polyfills")

    if ( options === undefined )
        options = {}
    kiteFetch.defaultOptions = options

    window.XMLHttpRequest = kiteXMLHttpRequest
    window.fetch = kiteFetch
}
