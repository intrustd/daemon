import { EventTarget } from "event-target-shim";

import React from 'react';
import ReactDom from 'react-dom';

import { FlockClient } from './FlockClient.js';

import "./Authenticator.scss";

function loginToAppliance(flocks, appliance) {
    var attempts = flocks.map((flock, flockIndex) => () => {
        return new Promise((resolve, reject) => {
            var client = new FlockClient({ url: flock,
                                           appliance })

            var onError = (e) => {
                removeEventListeners()
                if ( flockIndex == flocks.length ) {
                    reject()
                } else {
                    resolve(attempts[flockIndex + 1]())
                }
            }
            var onSuccess = () => {
                resolve(client)
            }
            var removeEventListeners = () => {
                client.removeEventListener('error', onError)
                client.removeEventListener('needs-personas', onSuccess)
            }

            client.addEventListener('error', onError)
            client.addEventListener('needs-personas', onSuccess)
        })
    })

    if ( attempts.length > 0 ) {
        return attempts[0]()
    } else
        return Promise.reject('no-flocks')
}

class AuthenticationEvent {
    constructor(dev) {
        this.type = 'open'
        this.device = dev
    }
}

class AuthenticatorModal extends React.Component {
    constructor() {
        super()

        this.applianceNameRef = React.createRef()
        this.passwordRef = React.createRef()
        this.state = { }
    }

    render() {
        const E = React.createElement;

        var loading = this.state.loading;

        var goButton = 'Go'

        if ( loading ) {
            goButton = E('i', {className: 'fa fa-fw fa-3x fa-spin fa-circle-o-notch'})
        }

        var error

        if ( this.state.error ) {
            error = E('div', {className: 'kite-form-error'},
                      this.state.error)
        }

        var personas

        if ( typeof this.state.personas == 'object' ) {
            console.log("doing personas", this.state.personas.length)
            if ( this.state.personas.length == 0 ) {
            } else {
                personas = E('div', {className: 'kite-form-row'},
                             E('ul', {className: 'kite-persona-list'},
                               this.state.personas.map(
                                   (p, ix) => {
                                       var loginBox

                                       if ( this.state.selectedPersona == ix )
                                           loginBox = E('input', { className: 'kite-form-input', ref: this.passwordRef,
                                                                   onKeyDown: this.onKeyDown.bind(this),
                                                                   type: 'password', placeholder: 'Password' })

                                       return E('li', {key: p.id, className: (this.state.selectedPersona == ix ? 'active' : ''),
                                                       onClick: () => { this.selectPersona(ix) }},
                                                E('div', {className: 'kite-display-name'}, p.displayname),
                                                loginBox)
                                   })))
            }
        }

        return E('div', {className: 'kite-auth-modal'},
                 E('header', {className: 'kite-auth-modal-header'},
                   E('h3', {}, 'Authenticate with Kite')),
                 E('p', {className: 'kite-auth-explainer'},
                   `The page at ${location.hostname} is requesting to log in to your Kite device.`),
                 E('div', {className: 'kite-login-form'},
                   error,
                   E('div', {className: 'kite-form-row'},
                     E('div', {className: 'form-control'},
                       E('input', {className: 'form-input', disabled: this.state.loading,
                                   name: 'appliance-name', id: 'appliance-name',
                                   placeholder: 'Appliance Name',
                                   ref: this.applianceNameRef,
                                   onKeyDown: this.onKeyDown.bind(this) }))),
                   personas,
                   E('div', {className: 'kite-form-row'},
                     E('button', {className: `kite-form-submit ${loading ? 'kite-form-submit--loading' : ''}`,
                                  disabled: loading,
                                  onClick: () => this.continueLogin() },
                       goButton))));
    }

    selectPersona(ix) {
        this.setState({selectedPersona: ix})
    }

    onKeyDown({keyCode}) {
        if ( keyCode == 13 )
            this.continueLogin()
    }

    continueLogin() {
        if ( this.state.state == 'login' ) {
            var personaId = this.state.personas[this.state.selectedPersona].id

            this.setState({loading: true})
            this.state.device.tryLogin(personaId, this.passwordRef.current.value)
                .then(() => this.props.onSuccess(this.state.device),
                      (e) => this.setState({device: undefined, personas: undefined, loading: false,
                                            error: 'Invalid login', state: 'connecting'}))
        } else {
            this.setState({loading: true})
            var applianceName = this.applianceNameRef.current.value
            loginToAppliance(this.props.flocks, applianceName)
                .then((dev) => this.getPersonas(dev),
                      (e) => {
                          this.setState({loading: false,
                                         error: 'Could not find appliance'})
                      })
        }
    }

    getPersonas(dev) {
        console.log("Got device", dev, dev.personas.length)
        this.setState({loading: false, error: false, state: 'login',
                       personas: dev.personas, device: dev})
    }
}

export class Authenticator extends EventTarget('open', 'error') {
    constructor(flocks, site) {
        super();

        this.modalContainer = document.createElement("div");
        this.modalContainer.classList.add("kite-auth-modal-backdrop");

        document.body.appendChild(this.modalContainer)

        ReactDom.render(React.createElement(AuthenticatorModal,
                                            { flocks: flocks,
                                              onError: this.onError.bind(this),
                                              onSuccess: this.onSuccess.bind(this) }),
                        this.modalContainer)
    }

    hide() {
        document.body.removeChild(this.modalContainer)
        delete this.modalContainer
    }

    onError() {
        this.hide()
        this.dispatchEvent(new Event('error'))
    }

    onSuccess(dev) {
        this.hide()
        this.dispatchEvent(new AuthenticationEvent(dev))
    }
}
