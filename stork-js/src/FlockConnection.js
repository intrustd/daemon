import { EventTarget } from "event-target-shim";
import { BufferParser } from "./Buffer.js";
import { SocketType,
         RequestAppControlMessage, RequestAppControlResponse,
         ConnectAppControlRequest, ConnectAppControlResponse } from "./SocketProxy.js";

export class InvalidProtocolName extends Error {
    constructor (proto_name) {
        super();
        this.message = proto_name + " is not a valid protocol name";
    }
}

export class FlockConnectionNotOpenError extends Error {
    constructor () {
        super();
        this.message = "Connection not open";
    }
}

export class AppNotOpenedError extends Error {
    constructor (app_name) {
        super();
        this.message = "The application " + app_name + " is not open";
    }
}

export class FlockConnectionErrorEvent {
    constructor ( conn, type, underlying ) {
        this.type = 'error';
        this.conn = conn;
        this.type = type;
        this.raw = underlying;
    }
}

export class FlockConnectionOpensEvent {
    constructor ( conn ) {
        this.type = 'open';
        this.connection = conn;
    }
}

export class FlockConnectionClosesEvent {
    constructor ( conn ) {
        this.type = 'close';
        this.connection = conn;
    }
}

export class FlockSocketOpensEvent {
    constructor ( sk ) {
        this.type = 'open';
        this.socket = sk;
    }
}

export class FlockSocketErrorEvent {
    constructor ( sk, err ) {
        this.type('error');
        this.socket = sk;
        this.error = err;
    }
}

export class FlockSocketClosesEvent {
    constructor ( sk ) {
        this.type = 'close';
        this.socket = sk;
    }
}

export class FlockSocketDataEvent {
    constructor ( sk, data ) {
        this.type = 'data';
        this.socket = sk;
        this.data = data;
    }
}

export class ApplicationDeniedError {
    constructor ( app_name, reason ) {
        this.app_name = app_name;
        this.reason = reason;
    }
}

export class FlockSocket extends EventTarget {
    constructor ( flock_conn, endpoint ) {
        super();
        this.conn = flock_conn;
        this.state = 'connecting';
        this.endpoint = endpoint;

        switch ( endpoint.type ) {
        case 'tcp':
            this.data_chan = this.conn.newDataChannel({});
            this.stream = true;
            this.start_connection = () => { this.start_tcp(endpoint.port); };
            break;
        case 'udp':
            var end_udp = () => { this.removeEventListener('open', end_udp); this.end_udp(); }
            this.data_chan = this.conn.newDataChannel({ ordered: false,
                                                        maxRetransmits: 0 });
            this.retransmits_left = 7;
            this.retransmit_interval = 100;
            this.stream = false;
            this.start_connection = () => { this.start_udp(endpoint.port); };
            this.addEventListener('open', end_udp);
            break;
        default:
            throw new InvalidProtocolName(endpoint.type);
        }

        this.data_chan.onopen = () => {
            this.start_connection();
        }

        this.data_chan.onclose = () => {
            this.dispatchEvent(new FlockSocketClosesEvent(this));
        }

        this.data_chan.onmessage = (e) => {
            switch ( this.state ) {
            case 'connecting':
                // Check to see if the connection is valid; if it is, set state to connected
                var parser = new BufferParser(e.data);
                var rsp = new ConnectAppControlResponse(parser);
                if ( rsp.error ) {
                    console.error("Got error while connecting", rsp.errno);
                    this.state = 'error';
                    this.dispatchEvent(new FlockSocketErrorEvent(this, 'system-error:' + rsp.errno));
                } else {
                    console.log("Connected socket");
                    this.dispatchEvent(new FlockSocketOpensEvent(this));
                    this.state = 'connected';
                }
                break;
            case 'connected':
                this.dispatchEvent(new FlockSocketDataEvent(this, e.data));
                break;
            case 'disconnected':
                console.error("FlockSocket got message while disconnected");
                break;
            case 'error':
                console.warning("Ignaring data on errored FlockSocket");
                break;
            default:
                console.error("FlockSocket has invalid state ", this.state);
            }
        }
    }

    close() {
        this.data_chan.close()
    }

    send(data) {
        if ( this.state == 'connected' )
            this.data_chan.send(data);
    }

    send_connection_request(sk_type, port) {
        var req = new ConnectAppControlRequest(sk_type, port, this.endpoint.app);
        this.data_chan.send(req.write().toArrayBuffer());
    }

    start_tcp(port) {
        this.send_connection_request(SocketType.SOCK_STREAM, port);
    }

    start_udp(port) {
        this.send_connection_request(SocketType.SOCK_DGRAM, port);

        this.retransmits_left -= 1;
        if ( this.retransmit_left > 0 ) {
            this.udp_retransmit_timer = setTimeout(this.retransmit_interval, () => { start_udp(port); });
            this.retransmit_interval *= 2;
        } else {
            this.state = 'disconnected';
            this.dispatchEvent(new FlockSocketErrorEvent(this, 'timeout'));
        }
    }

    end_udp() {
        clearTimeout(this.udp_retransmit_timer);
        delete this.udp_retransmit_timer;
    }
}

export class FlockConnection extends EventTarget {
    constructor ( flock, device_name, persona_id, apps_requested ) {
        super();

        this.flock = flock;
        this.device_name = device_name;
        this.persona_id = persona_id;
        this.apps_requested = apps_requested;

        this.logging_in = false;
        this.rtc_conn = null;
        this.rtc_control_channel = null;
        this.rtc_stream_number = 0;

        this.applications = {};
    }

    login ( creds ) {
        if ( !this.logging_in ) {
            this.logging_in = true;
            this.rtc_conn = null;

            this.applications = {};
            this.flock.loginToDeviceWithCreds(
                this.device_name, this.persona_id, creds,
                (err, iceServers) => {
                    if ( err ) {
                        this.logging_in = false;
                        console.error("Could not login: ", err);
                    } else {
                        console.log("Opening RTC connection", iceServers);
                        // We can now send ICE candidates to this flock server

                        iceServers = iceServers.map( (iceUri) => { return { urls: [ "stun:" + iceUri ] }; } );
                        console.log("Using ", iceServers);
                        this.rtc_conn = new RTCPeerConnection({ iceServers: iceServers });

                        var thisConnection = this;
                        this.rtc_control_channel = this.rtc_conn.createDataChannel('control', {protocol: 'control'});
                        this.rtc_control_channel.onopen = function () { thisConnection.controlChannelOpens(); };
                        this.rtc_control_channel.onclose = function () { thisConnection.controlChannelCloses(); };

                        this.rtc_conn.onicecandidate = (candidate) => { this.onIceCandidate(candidate); };

                        this.rtc_conn.createOffer((sdp) => { this.onOfferCreation(sdp) },
                                                  (error) => { this.offerCreationError(error) });
                    }
                });
        }
    }

    onOfferCreation(sdp) {
        console.log("Created offer with SDP", sdp);
        console.log("Full sdp", sdp.sdp);
        this.rtc_conn.setLocalDescription(sdp, () => {
            console.log("Set local description", sdp);
            this.flock.sendSessionDescription(sdp.sdp);
        }, this.offerCreationError);
    }

    onIceCandidate(candidate) {
        if ( candidate.candidate ) {
            console.log("Send ice candidate", candidate);
            this.flock.sendIceCandidate(candidate.candidate.candidate);
        } else {
            this.flock.requestDialAnswer(
                (answer) => {
                    console.log("Received answer", answer);
                    this.rtc_conn.setRemoteDescription({ type: "answer", sdp: answer.sdp })
                        .then(() => {
                            console.log("Setting ice candidates");
                            console.log(this.rtc_conn.remoteDescription);
                            answer.candidates.map((c) => { this.rtc_conn.addIceCandidate({candidate: c, sdpMid: "data"}); });
                        });
                },
                () => { console.error("Dial error"); });
        }
    }

    offerCreationError(error) {
        console.error("Could not create RTC offer", error);
        this.logging_in = false;
        this.rtc_conn = null;
        this.rtc_control_channel = null;
    }

    socketTCP (app_name, port) {
        console.log("Doing socketTCP");
        if ( this.applications.hasOwnProperty(app_name) ) {
            if ( this.rtc_conn !== null ) {
                return new FlockSocket(this, { type: 'tcp',
                                               app: this.applications[app_name],
                                               port: port });
            } else
                throw new FlockConnectionNotOpenError();
        } else
            throw new AppNotOpenedError(app_name);
    }

    newDataChannel(init) {
        var stream_name = 'stream' + this.rtc_stream_number;
        this.rtc_stream_number += 1;

        return this.rtc_conn.createDataChannel(stream_name, init);
    }

    requestApps(apps) {
        return new Promise((resolve, reject) => {
            var cur_app, cur_timer = null;
            var complete = () => {
                if ( cur_timer !== null ) {
                    clearTimeout(cur_timer);
                    cur_timer = null;
                }
                this.rtc_control_channel.removeEventListener('message', listener);
                resolve();
            };

            var canceled = () => {
                reject(new ApplicationDeniedError(cur_app, 'timeout'));
            };

            var go = () => {
                if ( apps.length == 0 ) {
                    complete();
                } else {
                    do {
                        cur_app = apps[0];

                        if ( apps.length > 0 )
                            apps.splice(0, 1);
                    } while ( this.applications.hasOwnProperty(cur_app) &&
                              apps.length > 0 );

                    if ( apps.length == 0 && this.applications.hasOwnProperty(cur_app) ) {
                        // We have all applications
                        complete();
                    } else {
                        var msg = new RequestAppControlMessage(cur_app);
                        cur_timer = setTimeout(canceled, 30000);
                        this.rtc_control_channel.send(msg.write().toArrayBuffer());
                    }
                }
            }

            var listener = ( e ) => {
                console.log("Got message event", e);

                if ( cur_timer !== null ) {
                    clearTimeout(cur_timer);
                    cur_timer = null;
                }

                var parser = new BufferParser(e.data);
                var rsp = new RequestAppControlResponse(parser);
                if ( rsp.error ) {
                    // TODO what error?
                    reject(new ApplicationDeniedError(cur_app, 'unknown'));
                } else {
                    this.applications[cur_app] = rsp.app_descriptor;
                }
                go();
            };
            this.rtc_control_channel.addEventListener('message', listener);

            go();
        });
    }

    controlChannelOpens () {
        // Now, we should request each app
        var apps = this.apps_requested.slice();

        // Attempt to send data on channel
        console.log("Requesting apps");
        this.requestApps(apps)
            .then(() => { this.dispatchEvent(new FlockConnectionOpensEvent(this)); })
            .catch((e) => {
                console.error(e);
                this.controlChannelCloses();
                this.dispatchEvent(new FlockConnectionErrorEvent(this, 'could-not-open-apps', e));
            });
    }

    controlChannelCloses () {
        if ( this.rtc_control_channel ) {
            this.rtc_control_channel.close();
        }
        if ( this.rtc_conn ) {
            this.rtc_conn.close();
        }

        this.logging_in = false;
        this.rtc_conn = null;
        this.rtc_control_channel = null;
        this.rtc_stream_number = 0;
        this.dispatchEvent(new FlockConnectionClosesEvent(this));
    }
};
