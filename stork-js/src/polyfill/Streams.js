var base64js = require('base64-js')

if (!ArrayBuffer.transfer) {
    ArrayBuffer.transfer = function(source, length) {
        if (!(source instanceof ArrayBuffer))
            throw new TypeError('Source must be an instance of ArrayBuffer');
        if (length <= source.byteLength)
            return source.slice(0, length);
        var sourceView = new Uint8Array(source),
            destView = new Uint8Array(new ArrayBuffer(length));
        destView.set(sourceView);
        return destView.buffer;
    };
}

export function BlobReader(blob) {
    var offset = 0
    var done = false
    var readSlice = ( offs, sz ) => {
        sz = Math.max(sz, 4096)
        return new Promise((resolve, reject) => {
            var chunk = blob.slice(offs, offs + sz)
            var reader = new FileReader()
            reader.onloadend = () => {
                offset += reader.result.byteLength
                resolve(reader.result)
            }
            reader.onerror = (e) => {
                console.error("Rejecting read file", e)
                reject(e)
            }

            reader.readAsArrayBuffer(chunk)
        })
    }

    var enqueueNext = (controller) => {
        return readSlice(offset, controller.desiredSize)
            .then((chunk) => {
                if ( chunk.byteLength == 0 ) {
                    if ( !done ) {
                        done = true
                        controller.close()
                    }
                } else {
                    controller.enqueue(chunk)
                }
            })
    }

    return new ReadableStream({
        start(controller) {
            return enqueueNext(controller)
        },

        pull(controller) {
            return enqueueNext(controller)
        }
    })
}

export class Base64Encoder {
    constructor() {
        var buffer = null

        var nextChunk, submitChunk, signalError, onChunkProcessed

        var complete = () => {
            submitChunk = (chunk) => { console.error("Chunk submitted after completion") }
            signalError = (e) => { console.error("Error signalled after completion") }
        }
        var makeNextChunk = () => {
            nextChunk = new Promise((resolve, reject) => {
                submitChunk = ({done, chunk}) => {
                    if ( done ) complete()
                    else
                        makeNextChunk()

                    resolve({done, chunk})
                    onChunkProcessed()
                }
                signalError = (e) => {
                    complete()
                    reject(e)
                }
            })
        }

        makeNextChunk()

        var readNext = (controller) => {
            if ( nextChunk === null ) return

            var ret =
                nextChunk.then(
                    ({done, chunk}) => {
//                        console.log("Enqueuing chunk in cotroller", done)
                        if ( done )
                            controller.close()
                        else {
             //               console.log("enqueue", chunk)
                            controller.enqueue(chunk)
                        }
                    },

                    (e) => {
                        controller.abort(e)
                    })
            nextChunk = null;

            return ret
        }

        this.readable = new ReadableStream({
            start(controller) {
                return readNext(controller)
            },

            pull(controller) {
                return readNext(controller)
            }
        })

        this.writable = new WritableStream({
            write(chunk) {
                return new Promise((resolve, reject) => {
                    if ( typeof chunk == 'string' ) {
                        var enc = new TextEncoder()
                        chunk = enc.encode(chunk).buffer
                    }

                    if ( buffer !== null ) {
                        var oldBufferLength = buffer.byteLength
                        var newChunk = ArrayBuffer.transfer(buffer, buffer.byteLength + chunk.byteLength)
                        new Uint8Array(newChunk, oldBufferLength).set(new Uint8Array(chunk))

                        chunk = newChunk
                    }

                    var extraBytes = chunk.byteLength % 3
                    var canEncode = chunk.byteLength - extraBytes

                    if ( extraBytes > 0 )
                        buffer = chunk.slice(canEncode, canEncode + extraBytes)
                    else
                        buffer = null

                    if ( canEncode > 0 ) {
                        var encodable = new Uint8Array(chunk, 0, canEncode)
                        var asBase64 = new TextEncoder().encode(base64js.fromByteArray(encodable)).buffer

                        // Do encode
                        onChunkProcessed = resolve
                        submitChunk({ chunk: asBase64, done: false })
                    } else
                        resolve()
                })
            },

            close(controller) {
                if ( buffer !== null ) {
                    submitChunk({ chunk: base64js.fromByteArray(buffer), done: false })
                }
                submitChunk({ chunk: new ArrayBuffer(0), done: true })
            }
        }, new ByteLengthQueuingStrategy({highWaterMark: 1024}))
    }
}
