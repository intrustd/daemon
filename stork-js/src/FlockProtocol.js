import { DynamicArrayBuffer, BufferParser } from "./Buffer.js";

const PERSONA_ID_LENGTH = 64;
const USER_ADMIN_APP = 'stork+app:stork.net/user-admin';

export class Command {
    constructor (name) {
        this.name = name;
    }

    write() {
        var buf = new DynamicArrayBuffer();
        buf.putUint32(this.name);

        return buf;
    }
}
Command.Names = {
    RegisterDevice: 0x00000001,
    LoginToDevice:  0x00000002,
    DialSession:   0x00000003,

    StartLogin:     0xFFFFFFFE
};

export class LoginToDeviceCommand extends Command {
    constructor (version, nm) {
        if ( typeof nm != "string" )
            throw new TypeError("LoginToDeviceCommand: the device name must be a string");
        if ( typeof version != "number" )
            throw new TypeError("LoginToDeviceCommand: the protocol version must be a number");

        super(Command.Names.LoginToDevice);
        this.device_name = nm;
        this.proto_version = version;
        this.credentials = null;
    }

    add_credentials(creds) {
        if ( creds instanceof Credentials ) {
            this.credentials = creds;
        } else
            throw new TypeError("LoginToDeviceCommand.add_credentials: expected Credentials");
    }

    write() {
        var buf = super.write();
        buf.putUint32(this.proto_version)
            .putVarLenString(this.device_name);
        if ( this.credentials !== null )
            this.credentials.write(buf);
        return buf;
    }
}

export const DIAL_TYPE_DONE = 0;
export const DIAL_TYPE_SDP = 1;
export const DIAL_TYPE_ICE = 2;
export class DialSessionCommand extends Command {
    constructor(dial_type, data, token) {
        if ( dial_type != DIAL_TYPE_SDP &&
             dial_type != DIAL_TYPE_ICE &&
             dial_type != DIAL_TYPE_DONE )
            throw new TypeError("Invalid dial type: " + dial_type);

        if ( typeof data != "string" )
            throw new TypeError("Expected dial data to be a string");

        if ( token === null || token === undefined )
            token = "";

        if ( typeof token != "string" )
            throw new TypeError("Expected dial token to be a string");

        super(Command.Names.DialSession);

        this.dial_type = dial_type;
        this.token = token;
        this.data = data;
    }

    write() {
        var buf = super.write();
        buf.putUint8(this.dial_type).putVarLenString(this.token).putVarLenString(this.data);
        return buf;
    }
}

export class ApplicationIdentifier {
    constructor(uri) {
        var a = document.createElement('a');
        a.href = uri;
        if ( a.protocol != "stork+app:" )
            throw new TypeError("ApplicationIdentifier: invalid protocol " + a.protocol);

        this.domain = a.hostname;
        this.app_id = a.pathname.split('/')[1];
    }

    write(buf) {
        buf.putVarLenString(this.domain)
            .putVarLenString(this.app_id);
    }
}

export class Credentials {
    constructor(persona_id, creds, apps) {
        this.persona_id = persona_id
        this.creds = creds
        this.apps =
            apps.filter((app) => { return app != USER_ADMIN_APP; })
            .map( (app_uri) => { return new ApplicationIdentifier(app_uri); });
        this.requires_user_admin = apps.some((app) => { return app == USER_ADMIN_APP; });
    }

    write (buf) {
        buf.putFixedLenString(64, this.persona_id)
            .putVarLenString(this.creds)
            .putUint8(this.requires_user_admin ? 1 : 0)
            .putList(this.apps, (app) => { app.write(buf); });
    }
}

export class Response {
    constructor (parser_or_response_code) {
        if ( parser_or_response_code instanceof ArrayBuffer )
            parser_or_response_code = new BufferParser(parser_or_response_code);
        this.backing = parser_or_response_code;

        if ( parser_or_response_code instanceof BufferParser ) {
            var parser = parser_or_response_code;
            this.status = parser.getUint16();
            console.log("Got status code", this.status);
        } else if ( typeof parser_or_response_code === "number" ){
            this.status = parser_or_response_code;
        } else
            throw new TypeError("Response must be called with ArrayBuffer, BufferParser or number");
    }

    get success() {
        return this.status == Response.Codes.Success;
    }
}
Response.Codes = {
    Success:        0x00000000,
    UnknownError:   0x00000001,
    DeviceAlreadyRegistered: 0x00000002,
    NoSuchDevice:   0x00000003,
    PersonasNotListed: 0x00000004,
    NoMoreEntries:  0x00000005,
    DeviceMalfunction: 0x00000006,
    InvalidCredentials: 0x00000007,
    InvalidDial: 0x00000008
};

export class LoginToDeviceResponse extends Response {
    constructor ( prc ) {
        super(prc);
        this.candidate = {};

        if ( this.status == Response.Codes.Success &&
             this.backing instanceof BufferParser) {
            // Attempt to parse persona candidate
            var backing = this.backing;
            var candidate = this.candidate;
            this.backing.getList(function () {
                var key = backing.getVarLenString();
                var value = backing.getVarLenString();
                candidate[key] = value;
            });
        }
    }
}

export class DialResponse extends Response {
    constructor (prc) {
        super(prc);

        if ( this.status == Response.Codes.Success &&
             this.backing instanceof BufferParser ) {
            this.sdp = this.backing.getVarLenString();
            this.candidates = [];

            this.backing.getList(() => {
                this.candidates.push(this.backing.getVarLenString());
            });
        }
    }
}
