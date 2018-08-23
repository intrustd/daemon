import storkFetch from './FetchApi.js'
import storkXMLHttpRequest from './XhrApi.js'

export default function () {
    console.log("Installing Stork polyfills")
    window.XMLHttpRequest = storkXMLHttpRequest
    window.fetch = storkFetch
}
