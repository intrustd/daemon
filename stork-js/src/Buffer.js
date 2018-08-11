import utf8 from "utf8";

const ARRAY_STARTING_SIZE = 8;

export class DynamicArrayBuffer {
    constructor () {
        this.buffer = null;
        this.buffer_position = 0;
    }

    toArrayBuffer() {
        if ( this.buffer === null ) {
            return new ArrayBuffer(0);
        } else {
            return new DataView(this.buffer, 0, this.buffer_position);
        }
    }

    expandBuffer() {
        var new_size = this.buffer.byteLength * 2;
        var new_buffer = new ArrayBuffer(new_size);

        var old_array = new Uint8Array(this.buffer);
        var new_array = new Uint8Array(new_buffer);

        new_array.set(old_array);

        this.buffer = new_buffer;
    }

    inter(sz, method, d, le) {
        if ( this.buffer === null ) {
            this.buffer = new ArrayBuffer(Math.max(ARRAY_STARTING_SIZE, sz));
            return this.inter(sz, method, d, le);
        } else if ( (this.buffer_position + sz) > this.buffer.byteLength ) {
            this.expandBuffer();
            return this.inter(sz, method, d, le);
        } else {
            var dv = new DataView(this.buffer, this.buffer_position, sz);
            dv[method](0, d, le);

            this.buffer_position += sz;

            return this;
        }
    }

    putUint8(u, le)  { return this.inter(1, "setUint8", u, le); }
    putUint16(u, le) { return this.inter(2, "setUint16", u, le); }
    putUint32(u, le) { return this.inter(4, "setUint32", u, le); }

    putInt8(u, le)   { return this.inter(1, "setInt8", u, le); }
    putInt16(u, le)  { return this.inter(2, "setInt16", u, le); }
    putInt32(u, le)  { return this.inter(4, "setInt32", u, le); }

    putVarLenString(s, le) {
        if ( typeof s !== "string" )
            throw new TypeError("putVarLenString: the argument must be a string");

        s = utf8.encode(s);

        this.putUint32(s.length, le);

        for ( var i = 0; i < s.length; i++ ) {
            this.putUint8(s.charCodeAt(i));
        }

        return this;
    }

    putFixedLenString(len, s, fill) {
        if ( typeof s !== "string" )
            throw new TypeError("putFixedLenString: the argument must be a string");

        if ( typeof len !== "number" )
            throw new TypeError("putFixedLenString: the length argument must be a number");

        if ( typeof fill !== "number" || fill > 255 )
            fill = 0;

        var i = 0;
        for ( ; i < len && i < s.length; ++i )
            this.putUint8(s.charCodeAt(i));

        for ( ; i < len; ++i )
            this.putUint8(fill);

        return this;
    }

    putList(a, cb) {
        this.putUint32(a.length);
        for ( var i = 0; i < a.length; ++i )
            cb(a[i]);

        return this;
    }
};

export class BufferParser {
    constructor (rsp) {
        if ( !(rsp instanceof ArrayBuffer) )
            throw new TypeError("BufferParser constructor must be called with ArrayBuffer object");

        this.buffer = rsp;
        this.buffer_position = 0;
    }

    fetch(sz, method, le) {
        if ( (this.buffer_position + sz) > this.buffer.byteLength )
            throw new RangeError("Attempt to parse past end of buffer");

        var dv = new DataView(this.buffer, this.buffer_position, sz);
        var ret = dv[method](0, le);

        this.buffer_position += sz;

        return ret;
    }

    getUint8(le)  { return this.fetch(1, "getUint8", le); }
    getUint16(le) { return this.fetch(2, "getUint16", le); }
    getUint32(le) { return this.fetch(4, "getUint32", le); }

    getInt8(le)   { return this.fetch(1, "getInt8", le); }
    getInt16(le)  { return this.fetch(2, "getInt16", le); }
    getInt32(le)  { return this.fetch(4, "getInt32", le); }

    getVarLenString(le) {
        var l = this.getUint32(le);
        var a = [];

        for ( var i = 0; i < l; ++i ) {
            a.push(this.getUint8());
        }

        var s = String.fromCharCode.apply(null, a);

        return utf8.decode(s);
    }

    getList(cb, le) {
        var l = this.getUint32(le);
        var r = [];

        for ( var i = 0; i < l; i++ ) {
            r.push(cb());
        }

        return r;
    }
};
