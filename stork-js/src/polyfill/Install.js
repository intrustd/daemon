import kiteFetch from './FetchApi.js'
import kiteXMLHttpRequest from './XhrApi.js'

export default function () {
    console.log("Installing Kite polyfills")
    window.XMLHttpRequest = kiteXMLHttpRequest
    window.fetch = kiteFetch
}
