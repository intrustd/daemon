import { EventTarget } from "event-target-shim";

import vCardParser from "vcard-parser";

import { Response, LoginToDeviceResponse,
         LoginToDeviceCommand, Credentials,
         DialSessionCommand,  DialResponse,
         DIAL_TYPE_SDP, DIAL_TYPE_ICE, DIAL_TYPE_DONE } from "./FlockProtocol.js";
import { FlockConnection } from "./FlockConnection.js";

class FlockOpenEvent {
    constructor() {
        this.type = "open";
    }
};

class FlockErrorEvent {
    constructor(line) {
        this.type = "error";
        this.line = line;
    }
};

class FlockNeedsApplianceEvent {
    constructor(flk) {
        this.type = 'needs-appliance';
        this.flock = flk;
    }
}

class FlockNeedsPersonasEvent {
    constructor(flk) {
        this.type = 'needs-personas';
        this.flock = flk;
    }
}

const FlockClientState = {
    Error: 'error',
    Connecting: 'connecting', // currently in the process of choosing an appliance
    Connected: 'connected', // connected to an appliance via a flock
    CollectingPersonas: 'collecting-personas',
    ReadyToLogin: 'ready-to-login', // personas collected, ready to log in
    StartIce: 'start-ice', // ICE is starting
    OfferReceived: 'offer-received', // Offer is received
    AnswerSent: 'answer-sent',
    Complete: 'ice-complete'
}

const iceServers = [ { urls: [ "stun:stun.stunprotocol.org" ] } ]

export class FlockClient extends EventTarget {
    constructor (options) {
        super();

        if ( !options.hasOwnProperty('url') )
            throw TypeError('\'url\' property required on options');

        var url = new URL(options.url);
        console.log("Got options", options);

        if ( options.hasOwnProperty('appliance') ) {
            console.log("Adding path", encodeURIComponent(options.appliance));
            url.pathname = '/' + encodeURIComponent(options.appliance);
            console.log("Path is now", url.pathname, url);
            this.state = FlockClientState.Connected;
            this.appliance = options.appliance;
        } else {
            url.pathname = '/';
            this.state = FlockClientState.Connecting;
        }

        this.personas = [];
        this.websocket = new WebSocket(url.href);

        var thisFlockClient = this;
        this.websocket.addEventListener('open', function (evt) {
            thisFlockClient.dispatchEvent(new FlockOpenEvent());
        });
        this.websocket.addEventListener('message', (evt) => {
            var line = this.parseLine(evt.data)
            console.log("Got websocket message", evt.data);
            if ( line ) {
                switch ( this.state ) {
                case FlockClientState.Connecting:
                    break;
                case FlockClientState.Connected:
                    // TODO get personas
                    switch ( line.code ) {
                    case 105:
                        this.personas = [];
                        this.state = FlockClientState.CollectingPersonas;
                        break;
                    default:
                        this.handleError(line);
                    }
                    break;
                case FlockClientState.CollectingPersonas:
                    switch ( line.code ) {
                    case 503:
                        console.log("Got 503");
                        this.personas = [];
                        break;
                    case 403:
                        console.log("Got 403");
                        // Authenticate now
                        this.state = FlockClientState.ReadyToLogin;
                        this.dispatchEvent(new FlockNeedsPersonasEvent(this));
                        break;
                    default:
                        this.handleError(line);
                    }
                    break;
                case FlockClientState.ReadyToLogin:
                    switch ( line.code ) {
                    case 200:
                        this.state = FlockClientState.StartIce;
                        break;
                    default:
                        this.handleError(line);
                    }
                    break;
                case FlockClientState.StartIce:
                    switch ( line.code ) {
                    case 150:
                        this.rtc_connection = new RTCPeerConnection({ iceServers: iceServers });
                        this.rtc_channel = this.rtc_connection.createDataChannel('control', {protocol: 'control'})
                        this.rtc_channel.onopen = function () { console.log("channel opens") }
                        this.rtc_channel.onclose = function () { console.log('channel closes') }

                        this.rtc_connection.addEventListener('negotiationneeded',
                                                             (e) => { this.onNegotiationNeeded(e) })
                        break;
                    default:
                        this.handleError(line);
                    }
                    break;
                default:
                    break;
                }
            } else {
                if ( this.state == FlockClientState.CollectingPersonas ) {
                    this.parseVCardData(event.data);
                } else if ( this.state == FlockClientState.StartIce ) {
                    console.log("Got offer", event.data);
                    this.offer = event.data;
                } else {
                    this.sendError(new FlockErrorEvent(evt.data));
                }
            }
        });
    };

    onNegotiationNeeded (e) {
        console.log("NEGOTIATION NEEDED")
        this.rtc_connection.createOffer().then((e) => console.log("Expected offer", e.sdp))
        this.rtc_connection.setRemoteDescription({ type: 'offer',
                                                   sdp: this.offer})
            .then(() => { this.onSetDescription() },
                  (err) => { console.error("Could not set remote description", err) })
    }

    // Called when the remote description is set and we need to send the answer
    onSetDescription() {
        console.log("Set remote description");

        this.rtc_connection.addEventListener('icecandidate', (c) => { console.log("Got ice candidate", c) })
        this.rtc_connection.createAnswer()
            .then((answer) => {
                this.rtc_connection.setLocalDescription(answer)
                console.log("Got answer", answer.sdp)
            })
    }

    parseVCardData(vcard) {
        var exp_prefix = "KITE PERSONAS";
        if ( vcard.startsWith(exp_prefix) ) {
            vcard = vcard.slice(exp_prefix.length);
            var vcards = vcard.split("\nEND:VCARD");
            vcards = vcards.map((vc) => (vc + "\nEND:VCARD").trim()).filter((vc) => vc.length > 0)
            vcards = vcards.map((vc) => vCardParser.parse(vc))

            console.log("Got parsed vcards", vcards)

            vcards = vcards.map((vc) => {
                if ( vc.hasOwnProperty('X-KITEID') ) {
                    var ret = { displayname: vc['X-KITEID'][0].value,
                                id: vc['X-KITEID'][0].value };
                    if ( vc.hasOwnProperty('fn') )
                        ret.displayname = vc['fn'][0].value;
                    return ret;
                } else return null
            }).filter((vc) => vc !== null)

            this.personas.push(...vcards)
        } else
            console.error("Invalid vcard data", vcard);
    }

    isLoggedIn() {
        return this.state == FlockClientState.StartIce ||
            this.state == FlockClientState.OfferReceived ||
            this.state == FlockClientState.AnswerSent ||
            this.state == FlockClientState.Complete;
    }

    hasPersonas() {
        return this.state == FlockClientState.ReadyToLogin ||
            this.isLoggedIn();
    }

    parseLine (ln) {
        var comps = ln.split(' ')
        var rspCode = parseInt(comps[0])
        if ( rspCode == rspCode ) {
            return { code: rspCode,
                     line: ln }
        } else return null;
    }

    handleError (line) {
        switch ( line.code ) {
        case 404:
            if ( this.state == FlockClientState.Connecting ) {
                delete this.appliance;
                this.dispatchEvent(new FlockNeedsApplianceEvent(this));
                return;
            }
            break;
        default: break;
        }

        this.sendError(new FlockErrorEvent(line.line));
    }

    tryLogin ( personaId, creds ) {
        this.websocket.send(personaId)
        this.websocket.send(creds)

        return Promise.reject("could not login")
    }

    sendError (err) {
        this.state = FlockClientState.Error;
        this.websocket.close();
        this.dispatchEvent(err);
    }

    sendRequest (req) {
        var buffer = req.write();
        this.websocket.send(buffer.toArrayBuffer(), {binary: true});
    };

    sendSessionDescription(sdp) {
        var cmd = new DialSessionCommand(DIAL_TYPE_SDP, sdp);
        this.sendRequest(cmd);
    }

    sendIceCandidate(iceData) {
        var cmd = new DialSessionCommand(DIAL_TYPE_ICE, iceData);
        this.sendRequest(cmd);
    }

    startConnection(device_name, persona_id, apps) {
        return new FlockConnection(this, device_name, persona_id, apps);
    }

    static testFlock() {
        var flock = new FlockClient("ws://localhost:6854/");
        var httpParser = require('http-parser-js').HTTPParser;
        var myBuffer = require('buffer').Buffer;
        console.log("Test flock");

        flock.addEventListener("open", function() {
            console.log("Flock connection established");
            flock.loginToDevice("combustion toxicity maple semicolon", function (rsp) {
                if ( rsp.success ) {
                    console.log("Successful login, candidates are ", rsp);

                    var conn = flock.startConnection("combustion toxicity maple semicolon", "c12e34eb2dd3924ad58f7192008aa2bdd7931ce2fe1c75c6c3ea5bc57686132a", [ "stork+app://flywithkite.com/photos" ]);

                    conn.addEventListener('open', function() {
                        console.log("Open", conn.applications);
                        var socket = conn.socketTCP("stork+app://flywithkite.com/photos", 50051);
                        var respParser = new httpParser(httpParser.RESPONSE);
                        var decoder = new TextDecoder();

                        respParser[respParser.kOnHeaders] = respParser.onHeaders = function (headers, url) {
                            console.log("Got http response", headers, url);
                        }
                        respParser[respParser.kOnHeadersComplete] = respParser.onHeadersComplete = function (info) {
                            console.log("On headers complete", info);
                        }
                        respParser[respParser.kOnBody] = respParser.onBody = function (b) {
                            console.log("on body", b);
                        }

                        socket.addEventListener('open', function() {
                            console.log("photos socket opened. Sending HTTP/1.1 message");
                            socket.send("GET / HTTP/1.1\r\nHost: flywithkite.com\r\nAccept: text/json\r\nConnection: close\r\n\r\n");
                        });
                        socket.addEventListener('data', function(e) {
                            var dataStr = decoder.decode(e.data);
                            console.log("Got data", dataStr);

                            var dataBuffer = Buffer.from(e.data);
                            respParser.execute(dataBuffer);
                        })
                        socket.addEventListener('close', function(e) {
                            console.log("Socket closes");
                            respParser.finish();
                            console.log("response is ", respParser);
                        })
                        socket.addEventListener('error', function(e) {
                            console.error("Socket error", e, e.explanation);
                        })
                    });
                    conn.addEventListener('error', function (e) {
                        console.error("Error opening connection", e);
                    });

                    conn.login("creds");
                } else {
                    console.error("Could not login to device");
                }
            });
        });
    }
};

window.FlockClient = FlockClient;

// function FlockResponseEvent(response_buffer) {
//     Event.call(this, "response");
//     this.response = response_buffer;
//     return this;
// };

// FlockResponseEvent.prototype = Event.prototype;

// function FlockClient(websocket_endpoint) {
//     EventTarget.call(this);

//     // TODO catch connection errors
//     this.websocket = new WebSocket(websocket_endpoint);
//     this.websocket.binaryType = 'arraybuffer';

//     this.websocket.addEventListener("open", this.socketOpens);
//     this.websocket.addEventListener("message", this.socketReceives);

//     return this;
// };

// FlockClient.prototype = Object.create(EventTarget.prototype, {
//     socketOpens: function (event) {
//         this.dispatchEvent(new Event("open"));
//     },

//     socketReceives: function (event) {
//         this.dispatchEvent(new FlockResponseEvent(event.data));
//     },

//     sendRequest: function (request) {
//         var buffer = request.write();
//         this.websocket.send(buffer.toArrayBuffer(), { binary: true });
//     }
// });
// FlockClient.prototype.constructor = FlockClient;

// FlockClient.Commands = {
//     RegisterDevice: 0x00000001,
//     LoginToDevice:  0x00000002,
//     CreateBridge:   0x00000003,

//     StartLogin:     0xFFFFFFFE
// };

// FlockClient.ResponseCodes = {
//     Success:        0x00000000,
//     UnknownError:   0x00000001,
//     DeviceAlreadyRegistered: 0x00000002,
//     NoSuchDevice:   0x00000003
// };

// FlockClient.testFlock = function () {
//     var flock = new FlockClient("ws://localhost:6854/");
//     console.log("Testing flock");

//     flock.addEventListener("open", function () {
//         console.log("connection establised");
//     });
// };

//     // ws.onopen = function () {
//     //     console.log("Websocket open");

//     //     var device_name = "This is a test";

//     //     var message_buffer = new ArrayBuffer(4096);
//     //     var message = new DataView(message_buffer);

//     //     message.setUint32(0, FlockClient.Commands.LoginToDevice);
//     //     message.setUint32(4, 1);
//     //     message.setUint32(8, device_name.length);

//     //     for ( var i = 0; i < device_name.length; i += 1 ) {
//     //         message.setUint8(i + 12, device_name.charCodeAt(i));
//     //     }

//     //     ws.send(message_buffer, { binary: true });
//     // };

//     // ws.onmessage = function (evt) {
//     //     console.log("Websocket message", evt.data);
//     // };
// //}
