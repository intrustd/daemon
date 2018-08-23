import { EventTarget } from "event-target-shim";

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

class FlockResponseEvent {
    constructor(response_buffer) {
        this.type = "response";
        this.responseBuffer = response_buffer;
    }
};

export class FlockClient extends EventTarget {
    constructor (websocket_url) {
        super();

        this.websocket = new WebSocket(websocket_url);
        this.websocket.binaryType = 'arraybuffer';

        var thisFlockClient = this;
        this.websocket.addEventListener('open', function (evt) {
            thisFlockClient.dispatchEvent(new FlockOpenEvent());
        });
        this.websocket.addEventListener('message', function (evt) {
            thisFlockClient.dispatchEvent(new FlockResponseEvent(evt.data));
        });
    };

    sendRequest (req) {
        var buffer = req.write();
        this.websocket.send(buffer.toArrayBuffer(), {binary: true});
    };

    loginToDevice (device_name, callback) {
        var cmd = new LoginToDeviceCommand(1, device_name);

        var responseData = {
            success: true,
            hasHiddenCandidates: false,
            candidates: []
        };

        var responseListener = (evt) => {
            var response = new LoginToDeviceResponse(evt.responseBuffer);

            if ( response.status == Response.Codes.NoMoreEntries ) {
                this.removeEventListener('response', responseListener);
                callback(responseData);
            } else if ( response.status == Response.Codes.PersonasNotListed ) {
                responseData.candidates = [];
                responseData.hasHiddenCandidates = true;
                this.removeEventListener('response', responseListener);
                callback(responseData);
            } else if ( response.status == Response.Codes.NoSuchDevice ) {
                responseData.success = false;
                responseData.error = "No such device";
                this.removeEventListener('response', responseListener);
                callback(responseData);
            } else if ( response.success ) {
                responseData.candidates.push(response.candidate);
            } else {
                this.removeEventListener('response', responseListener);
                console.error("Invalid response code", response.status);

                responseData.success = false;
                responseData.error = "Invalid response code";

                callback(responseData);
            }
        };
        this.addEventListener('response', responseListener);
        this.sendRequest(cmd);
    }

    loginToDeviceWithCreds(device_name, persona_id, creds, cb) {
        var cmd = new LoginToDeviceCommand(1, device_name);
        console.log("Logging into device with credentials");

        cmd.add_credentials(new Credentials(persona_id, creds));

        var responseListener = (evt) => {
            var response = new Response(evt.responseBuffer);

            this.removeEventListener('response', responseListener);
            if ( response.status == Response.Codes.InvalidCredentials ) {
                cb("invalid-credentials", []);
            } else if ( response.status == Response.Codes.Success ) {
                cb(null, [ "stun.stunprotocol.org", "stun.ekiga.net" ]);
            } else {
                console.error("Invalid response code for login command: ", response.status);
                cb("unknown-error", []);
            }
        };
        this.addEventListener('response', responseListener);
        this.sendRequest(cmd);
    }

    sendSessionDescription(sdp) {
        var cmd = new DialSessionCommand(DIAL_TYPE_SDP, sdp);
        this.sendRequest(cmd);
    }

    sendIceCandidate(iceData) {
        var cmd = new DialSessionCommand(DIAL_TYPE_ICE, iceData);
        this.sendRequest(cmd);
    }

    requestDialAnswer(cb, err) {
        var cmd = new DialSessionCommand(DIAL_TYPE_DONE, "");

        var responseListener = (evt) => {
            var response = new DialResponse(evt.responseBuffer);

            this.removeEventListener('response', responseListener);
            if ( response.status == Response.Codes.Success ) {
                cb(response);
            } else {
                err();
            }
        }
        this.addEventListener('response', responseListener);
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
