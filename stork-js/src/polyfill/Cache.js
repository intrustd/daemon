import { Record, Map, Set } from 'immutable';

import { parseKiteAppUrl } from './Common.js';

import cachePolyfill from 'cache-polyfill/src/cache-storage.js';
console.log("CAche Polyfill", cachePolyfill)

const CacheKey = Record({ method: '', url: '' })

const CacheVersion = "v1-rc5";

class ResponsesCache {
    constructor(varyHeaders) {
        this.cache = Map()

        if ( varyHeaders !== undefined )
            this.varyHeaders = varyHeaders
    }

    updateVaryHeaders(newVary) {
        if ( !this.varyHeaders.equals(newVary) ) {
            this.cache = Map()
            this.varyHeaders = newVary
        }
    }

    match(headers) {
        var hdrKey = {}
        for ( var hdrNm of this.varyHeaders.values() ) {
            hdrKey[hdrNm] = headers.get(hdrNm)
        }
        hdrKey = Map(hdrKey)

        var cached = this.cache.get(hdrKey)
        if ( cached === undefined || cached === null )
            return Promise.resolve()
        else
            return Promise.resolve(cached)
    }

    put(headers, response) {
        // Otherwise, store the response
        var hdrKey = {};
        for ( var [hdrName, ...hdrValues] of headers.entries() ) {
            if ( this.varyHeaders.includes(hdrName) )
                hdrKey[hdrName] = hdrValues
        }
        hdrKey = Map(hdrKey)

        this.cache = this.cache.set(hdrKey, response)
        return Promise.resolve()
    }
}

class PrivateCache {
    constructor() {
        this.cache = Map()
    }

    shouldCacheHeader(hdrName, varyHeaders) {
        if ( varyHeaders.includes(hdrName) >= 0 )
            return true;

        return false;
    }

    put (request, response) {
        try {
            if ( !CacheableMethods[request.method] )
                return Promise.reject(new TypeError("This request is not cacheable due to its HTTP Method"))

            var varyHeaders = response.headers.get('vary')
            var cacheControl = parseCacheControl(response.headers.get('cache-control'))


            if ( varyHeaders === null )
                varyHeaders = []
            else
                varyHeaders = varyHeaders.split(',').map((s) => s.trim().toLower())
            varyHeaders = Set(varyHeaders)

            if ( cacheControl.cacheability == Cacheability.INVISIBLE ) {
                return Promise.resolve()
            }

            // Store the response

            var cacheKey = CacheKey({
                method: request.method,
                url: request.url
            })

            var responsesCache = this.cache.get(cacheKey)
            if ( responsesCache === undefined || responsesCache === null ) {
                responsesCache = new ResponsesCache(varyHeaders)
            }

            responsesCache.updateVaryHeaders(varyHeaders)

            return responsesCache.put(request.headers, response)
                .then(() => {
                    this.cache = this.cache.set(cacheKey, responsesCache)
                })
        } catch (e) {
            return Promise.reject(e)
        }
    }

    match(request) {
        if ( !CacheableMethods[request.method] ) return Promise.resolve()

        var cacheKey = CacheKey({
            method: request.method,
            url: request.url
        })

        var responsesCache = this.cache.get(cacheKey)
        if ( responsesCache === null || responsesCache === undefined )
            return Promise.resolve()
        else {
            return responsesCache.match(request.headers)
                .then((rsp) => {
                    var responseInit = Object.assign({}, rsp)
                    delete responseInit.bodyBlob
                    return new Response(rsp.bodyBlob, responseInit)
                })
        }
    }
}

const CacheableMethods = { 'GET': true }

const Cacheability = {
    PUBLIC: Symbol('PUBLIC'),
    PRIVATE: Symbol('PRIVATE'),
    NO_CACHE: Symbol('NO_CACHE'),
    ONLY_IF_CACHED: Symbol('ONLY_IF_CACHED'),
    INVISIBLE: Symbol('INVISIBLE') // no-store
}

function parseCacheControl(ctl) {
    var ret = {
        visibility: Cacheability.PUBLIC,
        cacheability: Cacheability.PUBLIC,
        maxAge: 0,
        mustRevalidate: false,
        immutable: false,
        transformable: true
    }

    if ( ctl === null ) return ret;
    ctl = ctl.split(',').filter((c) => c.length > 0)
        .map((s) => s.trim())

    var updateCacheability = (c) => {
        if ( ret.cacheability != Cacheability.INVISIBLE )
            ret.cacheability = c;

        if ( c == Cacheability.PUBLIC ||
             c == Cacheability.PRIVATE ) {
            if ( ret.visibility != Cacheability.PRIVATE )
                ret.visibility = c;
        }
    }

    for ( var dir of ctl ) {
        switch ( dir ) {
        case 'public':
            updateCacheability(Cacheability.PUBLIC);
            break;

        case 'private':
            updateCacheability(Cacheability.PRIVATE);
            break;

        case 'no-cache':
            updateCacheability(Cacheability.NO_CACHE);
            break;

        case 'only-if-cached':
            updateCacheability(Cacheability.ONLY_IF_CACHED);
            break;

        case 'no-store':
            updateCacheability(Cacheability.INVISIBLE);
            break;

        case 'must-revalidate':
            ret.mustRevalidate = true;
            break;

        case 'immutable':
            ret.immutable = true;
            break;

        case 'no-transform':
            ret.transformable = false;
            break;

        default:
            if ( dir.startsWith('max-age=') ) {
                var maxAge = parseInt(dir.slice('max-age='.length))
                if ( typeof maxAge == 'number' )
                    ret.maxAge = maxAge
            }
            break;
        }
    }

    return ret
}

class KiteCacheAdaptor {
    constructor(cache, domain) {
        this.domain = domain
        this.underlying = cache
    }

    rewriteKiteRequest(request) {
        var url = parseKiteAppUrl(request.url)

        if ( url.isKite ) {
            var url = `http://${this.domain}${url.path}`
            var requestInit = {
                method: request.method,
                headers: request.headers,
                mode: request.mode,
                credentials: request.credentials,
                cache: request.cache,
                redirect: request.redirect,
                referrer: request.referrer,
                integrity: request.integrity
            }

            request = new Request(url, requestInit)
        }

        return request
    }

    match(request) {
        request = this.rewriteKiteRequest(request)

        return this.underlying.match(request)
    }

    put (request, response) {
        var bodyBlob = response.bodyBlob

        var responseInit = Object.assign({}, response)
        delete responseInit.bodyBlob
        var response = new Response(bodyBlob, responseInit)
        request = this.rewriteKiteRequest(request)

        return this.underlying.put(request, response)
    }
}

export class CacheControl {
    constructor ( flockServerAddress, applianceName, personaId, appId ) {
        this.flock = flockServerAddress
        this.applianceName = applianceName
        this.personaId = personaId
        this.appId = appId

        this.cacheName = this.makeCanonicalName()

        var appUrl = parseKiteAppUrl(this.appId)

        console.log("Got cache polyfill", cachePolyfill)
        if ( window.caches ) {
            this.publicCache = window.caches.open(this.cacheName).then((cache) => new KiteCacheAdaptor(cache, appUrl.domain))
        } else {
            this.publicCache = cachePolyfill.caches.open(this.cacheName).then((cache) => new KiteCacheAdaptor(cache, appUrl.domain))
        }
        this.privateCache = Promise.resolve(new PrivateCache())
    }

    makeCanonicalName() {
        var flockUrl = new URL(this.flock)
        var flockNmNorm = `${flockUrl.protocol}-${flockUrl.hostname}-${flockUrl.port}`
        var applNmNorm = this.applianceName.split(' ').join('-')

        var appUrl = parseKiteAppUrl(this.appId)
        var appDomain = appUrl.domain
        var appName = appUrl.appId

        return `${CacheVersion}:${flockNmNorm}:${applNmNorm}:${this.personaId}:${appDomain}-${appName}`
    }

    shouldCache(request) {
        return !!CacheableMethods[request.method];
    }

    cacheResponse(request, responseInit, bodyBlob) {
        if ( !this.shouldCache(request) ) return Promise.resolve()

        var headers = responseInit.headers || new Headers();

        var cacheControl = parseCacheControl(headers.get('cache-control'))

        // By default, the method, the URL, and the Content-Type header are cached
        var cache = this.privateCache

        if ( cacheControl.visibility == Cacheability.PUBLIC ) {
            cache = this.publicCache
        }

        return cache.then((cache) => cache.put(request, Object.assign({}, responseInit, { bodyBlob })))
    }

    matchRequest(request) {
        var privateMatch = this.privateCache.then((cache) => cache.match(request))
        var publicMatch = this.publicCache.then((cache) => cache.match(request))

        return Promise.all([privateMatch, publicMatch])
            .then(([privateResult, publicResult]) => {
                if ( privateResult !== undefined ) {
                    return privateResult;
                } else if ( publicResult !== undefined ) {
                    return publicResult;
                } else
                    return undefined;
            })
    }
}
