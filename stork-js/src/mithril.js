import m from 'mithril';

import { parseKiteAppUrl } from './polyfill/Common.js';

function getXhrImage(xhr, opts) {
    xhr.response
}

export function StorkImage () {
    var url = null;
    var srcUrl = null;
    var curBlob = null;

    var updateUrl = (newUrl) => {
        url = newUrl;
        var parsed = parseKiteAppUrl(url);
        if ( parsed.isKite ) {
            srcUrl = "about:blank";
            console.error("TODO kite images")
        } else {
            srcUrl = "about:blank";
            m.request({
                method: 'GET',
                url: url,
                config: (xhr) => { xhr.responseType = 'blob'; return xhr; },
                extract: (xhr) => {
                    return { contentType: xhr.getResponseHeader('content-type'),
                             body: xhr.response }
                },
                deserialize: (d) => { return d; }
            }).then(({contentType, body}) => {
                curBlob = URL.createObjectURL(body)
                srcUrl = curBlob;
                console.log("Got blob", srcUrl)
            })
            m.redraw()
        }
    }

    return {
        oncreate: (vnode) => {
            updateUrl(vnode.attrs.src);
        },

        onbeforeupdate: (vnode) => {
            console.log("before update", vnode);
            return true;
        },

        view: (vnode) => {
            console.log("view called", srcUrl)
            var attrs = Object.assign({}, vnode.attrs)
            attrs.src = srcUrl;
            delete attrs.cls;

            if ( srcUrl )
                return m("img" + (vnode.attrs.cls || ""), attrs)
            else
                return "Loading"
        }
    }
}
