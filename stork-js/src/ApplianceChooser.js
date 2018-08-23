import { EventTarget } from "event-target-shim";
import m from "mithril";
import 'bootstrap';
import jQuery from 'jquery';
import "./ApplianceChooser.scss";

export class ApplianceChooserCancelsEvent {
    constructor () {
        this.type = 'cancel'
    }
}

export class ApplianceChooserChoosesEvent {
    constructor(device, candidateId) {
        this.type = 'persona-chosen'
        this.device = device
        this.persona = candidateId
    }
}

const ApplianceChooserState = {
    NONE: 'NONE',
    LOADING: 'LOADING',
    CANDIDATES_LOADED: 'CANDIDATES_LOADED',
    CANDIDATES_HIDDEN: 'CANDIDATES_HIDDEN',
    ERROR: 'ERROR'
}

function PersonaList(vnode) {
    var current = null;

    return {
        view: (vnode) => {
            var candidates = vnode.attrs.candidates
            var chooser = vnode.attrs.chooser

            console.log("Candidates", candidates)

            var candidateEls =
                candidates.map(({id, token}) => {
                    var elName = "li.list-group-item";
                    if ( id == current )
                        elName += ".active";

                    return m(elName,
                             { id,
                               onclick: () => { current = id; } },
                             id)
                })

            var activationButton = []
            if ( current !== null )
                activationButton = [
                    m("button.btn.btn-primary",
                      { onclick: () => { chooser.chooseCandidate(current) } },
                      "Login")
                ]

            return m("ul.persona-list.list-group",
                     [ candidateEls,
                       activationButton ]);
        }
    }
}

export class ApplianceChooser extends EventTarget {
    constructor (client) {
        super()

        this.client = client
        this.shown = false
        this.state = ApplianceChooserState.NONE

        this.show()
    }

    show() {
        this.shown = true

        this.container = document.createElement("div")
        this.container.className = "stork-application-chooser-container"

        document.body.appendChild(this.container)

        this.m$component = {
            view: () => { return this.view() },
            oncreate: (n) => { this.oncreate(n) }
        };

        m.mount(this.container, this.m$component)
    }

    hide() {
        var container = this.container

        this.shown = false
        this.container = null

        if ( this.rootVnode )
            jQuery(this.rootVnode).modal('hide')

        if ( container !== null && container.parentNode )
            container.parentNode.removeChild(container)
    }

    canceled() {
        this.hide()
        this.dispatchEvent(new ApplianceChooserCancelsEvent())
    }

    chooseCandidate(candidateId) {
        console.log("Choosing candidate", candidateId)
        this.dispatchEvent(new ApplianceChooserChoosesEvent(this.deviceName, candidateId))
    }

    onenter(applianceName) {
        console.log("Going to lookup personas for device " + applianceName);
        this.state = ApplianceChooserState.LOADING
        this.deviceName = applianceName
        if ( this.hasOwnProperty('error') ) delete this.error
        if ( this.hasOwnProperty('candidates') ) delete this.candidates
        if ( this.hasOwnProperty('persona_component') ) delete this.persona_component
        this.client.loginToDevice(applianceName, (rsp) => {
            if ( rsp.success ) {
                if ( rsp.hasHiddenCandidates )
                    this.state = ApplianceChooserState.CANDIDATES_HIDDEN
                else {
                    this.state = ApplianceChooserState.CANDIDATES_LOADED
                    this.candidates = rsp.candidates
                    console.log("Got candidates", rsp)
                }
            } else {
                this.state = ApplianceChooserState.ERROR
                this.error = "Could not fetch personas"
                console.error("Could not fetch personas", rsp);
            }

            m.redraw()
        });
    }

    oncreate (vnode) {
        jQuery(vnode.dom)
            .modal('show')
            .on('hidden.bs.modal', () => {
                this.canceled()
            })

        this.rootVnode = vnode.dom
    }

    onupdate (vnode) {
        this.rootVnode = vnode.dom
    }

    view () {
        var body = m("div");
        switch ( this.state ) {
        case ApplianceChooserState.LOADING:
            body = m("div.loading", "Loading...")
            break
        case ApplianceChooserState.CANDIDATES_LOADED:
            body = m(PersonaList, { chooser: this, candidates: this.candidates })
            break
        case ApplianceChooserState.CANDIDATES_HIDDEN:
            body = m("div", "TODO Hidden candidates");
            break;
        case ApplianceChooserState.ERROR:
            body = m("div.alert.alert-danger", { role: "alert" }, this.error);
            break;
        case ApplianceChooserState.NONE:
        default:
            break;
        }

        return m(".stork-appliance-chooser.modal.fade",
                 { tabindex: "-1", role: "dialog",
                   "aria-labelledby": "stork-appliance-chooser-title",
                   "aria-hidden": "true" },
                 [
                     m(".modal-dialog", { role: "document" },
                       [ m(".modal-content", [
                           m(".modal-header", [
                               m("h5.modal-title#stork-appliance-chooser-title",
                                 "Log-in"),
                               m("button.close",
                                 { type: "button", "data-dismiss": "modal", "aria-label": "Close" },
                                 m("span", {"aria-hidden": "true"}, "×"))
                           ]),
                           m(".modal-body", [
                               m(".input-group", [
                                   m("input.form-control",
                                     { type: "text", placeholder: "Appliance Name",
                                       onkeyup: ({keyCode, target}) => {
                                           if ( keyCode == 13 ) this.onenter(target.value)
                                       },
                                       "aria-label": "Appliance Name" })
                               ]),
                               body
                           ])
                       ])]),
                 ])
    }
}

