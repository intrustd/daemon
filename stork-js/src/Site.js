// A site is a particular domain (HTTP realm) on a particular browser
//
// We use the browser's localStorage to store a site cookie. This
// cookie specifies the current flock url, appliance name, and
// persona, and a large token string.
//
// On startup, if there is an existing site, the credentials are
// automatically transmitted to the flock and the user is logged in.

export function resetSite() {
    localStorage.removeItem('$kite-flock')
    localStorage.removeItem('$kite-appliance')
    localStorage.removeItem('$kite-persona')
    localStorage.removeItem('$kite-token')
}

export function getSite() {
    var flockUrl = localStorage.getItem('$kite-flock')
    var applName = localStorage.getItem('$kite-appliance')
    var personaId = localStorage.getItem('$kite-persona')
    var token = localStorage.getItem('$kite-token')

    if ( typeof flockUrl !== 'string' ||
         typeof applName !== 'string' ||
         typeof personaId !== 'string' ||
         typeof token !== 'string' ) {
        resetSite()
        return null
    }

    return { flockUrl, appliance: applName, personaId, token }
}

