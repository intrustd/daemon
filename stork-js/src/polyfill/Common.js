export function parseStorkAppUrl(url) {
    var url_obj = new URL(url);
    var host = url_obj.pathname;

    switch ( url_obj.protocol ) {
    case 'stork+app:':
        if ( host.startsWith('//') ) {
            var info = host.substr(2).split('/');
            if ( info.length >= 2 ) {
                return { isStork: true,
                         domain: info[0],
                         appId: info[1],
                         path: '/' + info.slice(2).join('/'),
                         port: 50051 // TODO
                       };
            }
        }
        return { isStork: true, error: "Expected stork+app://app.domain/app-id" };
    default:
        return { isStork: false };
    }
}

export function storkAppCanonicalUrl( urlData ) {
    return 'stork+app://' + urlData.domain + '/' + urlData.appId;
}
