import { DynamicArrayBuffer } from "./Buffer.js";

const SCM_REQ_OPEN_APP = 1;
const SCM_REQ_CONNECT = 2

export const SocketType = {
    SOCK_STREAM: 1,
    SOCK_DGRAM:  2,
    SOCK_SEQPACKET: 5
};

export class RequestAppControlMessage {
    constructor ( app_name ) {
        this.app_name = app_name;
    }

    write () {
        var buffer = new DynamicArrayBuffer();
        buffer.putUint8(SCM_REQ_OPEN_APP)
            .putVarLenString(this.app_name)
        return buffer;
    }
}

export class RequestAppControlResponse {
    constructor ( parser ) {
        var byte = parser.getUint8();
        if ( (byte & 0x80) == 0 ) {
            console.error("This is not a response");
        }

        if ( byte & 0x40 ) {
            this.error = true;
            this.errno = parser.getUint32();
        } else {
            this.error = false;
            this.app_descriptor = parser.getUint32();
        }
    }
}

export class ConnectAppControlRequest {
    constructor ( sk_type, port, app, retries ) {
        if ( retries === undefined )
            retries = 7;

        this.retries = retries;
        this.sk_type = sk_type;
        this.port = port;
        this.app = app;
    }

    write () {
        var buffer = new DynamicArrayBuffer();
        buffer.putUint8(SCM_REQ_CONNECT)
            .putUint8(this.retries)
            .putUint8(this.sk_type)
            .putUint16(this.port)
            .putUint32(this.app);
        return buffer;
    }
}

export class ConnectAppControlResponse {
    constructor ( parser ) {
        var byte = parser.getUint8();
        if ( (byte & 0x80) == 0 ) {
            console.error("This is not a response");
        }

        if ( byte & 0x40 ) {
            this.error = true;
            this.errno = parser.getUint32();
        } else {
            this.error = false;
        }
    }
}
