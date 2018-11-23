export function parseKiteAppUrl(url) {
    var url_obj = new URL(url);
    var host = url_obj.pathname;

    switch ( url_obj.protocol ) {
    case 'kite+app:':
        if ( host.startsWith('//') ) {
            var info = host.substr(2).split('/');
            if ( info.length >= 2 ) {
                return { isKite: true,
                         app: info[0],
                         path: '/' + info.slice(1).join('/'),
                         port: 50051 // TODO
                       };
            }
        }
        return { isKite: true, error: "Expected kite+app://app.domain/" };
    default:
        return { isKite: false };
    }
}

export function kiteAppCanonicalUrl( urlData ) {
    return 'kite+app://' + urlData.app;
}
