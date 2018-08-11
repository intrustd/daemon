import { EventTarget } from "event-target-shim";

export class FlockConnection extends EventTarget {
    constructor ( flock, device_name, persona_id, apps_requested ) {
        super();

        this.flock = flock;
        this.device_name = device_name;
        this.persona_id = persona_id;
        this.apps_requested = apps_requested;

        this.logging_in = false;
        this.rtc_conn = null;
        this.rtc_data_channel = null;
    }

    login ( creds ) {
        if ( !this.logging_in ) {
            this.logging_in = true;
            this.rtc_conn = null;

            var that = this;
            this.flock.loginToDeviceWithCreds(
                this.device_name, this.persona_id, creds, this.apps_requested,
                (err, iceServers) => {
                    if ( err ) {
                        that.logging_in = false;
                        console.error("Could not login: ", err);
                    } else {
                        console.log("Opening RTC connection", iceServers);
                        // We can now send ICE candidates to this flock server

                        iceServers = iceServers.map( (iceUri) => { return { urls: [ "stun:" + iceUri ] }; } );
                        console.log("Using ", iceServers);
                        that.rtc_conn = new RTCPeerConnection({ iceServers: iceServers });
                        that.rtc_conn.onicecandidate = (candidate) => { this.onIceCandidate(candidate); };

                        that.rtc_data_channel = that.rtc_conn.createDataChannel('control', { protocol: 'stork-control' });
                        that.rtc_data_channel.onopen = function () { that.dataChannelOpens(); };
                        that.rtc_data_channel.onclose = function () { that.dataChannelCloses(); };

                        that.rtc_oob_channel = that.rtc_conn.createDataChannel('oob', { protocol: 'stork-control' });

                        that.rtc_conn.createOffer((sdp) => { this.onOfferCreation(sdp) },
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
        this.rtc_data_channel = null;
    }

    socketTCP (port) {
    }

    dataChannelOpens () {
        this.dispatchEvent(FlockConnectionOpensEvent());
    }

    dataChannelCloses () {
        this.logging_in = false;
        this.rtc_conn = null;
        this.rtc_data_channel = null;
        this.dispatchEvent(FlockConnectionClosesEvent());
    }
};
