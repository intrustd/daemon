import kiteFetch from './FetchApi.js'
import kiteXMLHttpRequest from './XhrApi.js'

export default function (options) {
    console.log("Installing Kite polyfills")

    if ( options === undefined )
        options = {}

    // Set this option if you want to enable explicit logins as part
    // of your app.
    if ( options.require_login ) {
        kiteFetch.require_login = true;
    }

    if ( options.permissions instanceof Array )
        kiteFetch.permissions = options.permissions
    else
        kiteFetch.permissions = []

    // TODO Add basic permissions

    window.XMLHttpRequest = kiteXMLHttpRequest
    window.fetch = kiteFetch
}
