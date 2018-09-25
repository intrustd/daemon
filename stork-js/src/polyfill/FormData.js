import{ BlobReader, Base64Encoder } from './Streams.js';

export function generateKiteBoundary() {
    var random = "";
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    for ( var i = 0; i < 16; ++i ) {
        var charIndex = Math.floor(Math.random() * chars.length)
        random += chars.charAt(charIndex)
    }

    var boundary = `----KiteFormBoundary${random}`
    return { boundary,
             contentType: `multipart/form-data; boundary=${boundary}` }
}

const FormDataMode = {
    BOUNDARY: Symbol('BOUNDARY'),
    FIELD: Symbol('FIELD'),
    STREAM: Symbol('STREAM'),
    WAITING: Symbol('WAITING'),
    DONE: Symbol('DONE')
};

export function makeFormDataStream(formData, boundary) {
    var items = formData.entries()[Symbol.iterator]()
    var currentItem = items.next()
    var sentItem = false

    var mode = { mode: FormDataMode.BOUNDARY }


    var enqueueNext = (controller) => {
        console.log("enqueueNext")
        if ( mode.mode == FormDataMode.DONE ) {
            controller.close()
            return
        }

        if ( currentItem.done ) {
            if ( sentItem ) {
                mode = { mode: FormDataMode.DONE }
                controller.enqueue(`--${boundary}--\r\n`)
            }
            controller.close()
        } else {
            switch ( mode.mode ) {
            case FormDataMode.BOUNDARY:
                console.log("Got entry", currentItem)

                sentItem = true
                controller.enqueue(`--${boundary}\r\n`)
                mode = { mode: FormDataMode.FIELD, name: currentItem.value[0],
                         value: currentItem.value[1] }
                enqueueNext(controller)
                break;

            case FormDataMode.FIELD:
                if ( mode.value instanceof File ) {
                    controller.enqueue(`Content-Disposition: form-data; name="${mode.name}"; filename="${mode.value.name}"\r\n`)
                    controller.enqueue(`Content-Type: ${mode.value.type}\r\n\r\n`)
//                    controller.enqueue('Content-transfer-encoding: base64\r\n\r\n')

                    var stream = BlobReader(mode.value)
//                    stream = stream.pipeThrough(new Base64Encoder())
                    mode = { mode: FormDataMode.STREAM, stream: stream.getReader() }
                } else {
                    console.error("Can't handle non-file", mode.value)
                    throw new TypeError("TODO can't handle non-files")
                }
                enqueueNext(controller)
                break;

            case FormDataMode.STREAM:
                mode.stream.read().then(({value, done}) => {
                    var chunk = value
                    if ( done ) {
                        currentItem = items.next()
                        controller.enqueue('\r\n')
                        mode = { mode: FormDataMode.BOUNDARY }
                        enqueueNext(controller)
                    } else {
                        if ( mode.mode == FormDataMode.WAITING ) {
                            console.log("Enqueue", chunk)
                            controller.enqueue(chunk)
                            mode = mode.oldMode;
                            enqueueNext(controller)
                        } else
                            console.error("Read chunk, but we are not waiting", mode)
                    }
                })
                mode = { mode: FormDataMode.WAITING, oldMode: mode }
                break;
            }
        }
    }

    return new ReadableStream({
        start (controller) {
            enqueueNext(controller)
        },

        pull (controller) {
            enqueueNext(controller)
        }
    })
}
