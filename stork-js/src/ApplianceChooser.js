import { EventTarget } from "event-target-shim";
import m from "mithril";
import 'bootstrap';
import jQuery from 'jquery';
import "./ApplianceChooser.scss";

export class ChooserCancelsEvent {
    constructor () {
        this.type = 'cancel'
    }
}

export class PersonaChooserChoosesEvent {
    constructor(device, id, creds) {
        this.type = 'persona-chosen'
        this.device = device
        this.personaId = id
        this.creds = creds
    }
}

export class ApplianceChooserChoosesEvent {
    constructor(device) {
        this.type = 'appliance-chosen'
        this.device = device
    }
}

function PersonaList(vnode) {
    var current = null;

    return {
        view: (vnode) => {
            var candidates = vnode.attrs.candidates
            var chooser = vnode.attrs.chooser

            console.log("Candidates", candidates)

            var candidateEls =
                candidates.map(({id, displayname}) => {
                    var elName = "li.list-group-item";
                    var active = id == current;
                    var body = m(".display-name", displayname);

                    if ( active ) {
                        elName += ".active";
                        body = [
                            m("form.uk-form", { onsubmit: (e) => {
                                e.preventDefault()
                                e.stopPropagation()

                                var creds = e.target.elements["password"].value
                                chooser.onchoose(current, creds)
                            }}, [
                                m(".display-name", displayname),
                                m(".uk-form-password", [
                                    m("input", {type: "password", name: "password"}),
                                    m("a.uk-form-password-toggle", {href: ""})
                                ]),
                                m("button", {type: "submit"}, "Login")
                            ])
                        ]
                    }

                    return m(elName,
                             { id,
                               onclick: () => { current = id; } },
                             body)
                })

            return m("ul.persona-list.list-group",
                     candidateEls);
        }
    }
}

class Chooser extends EventTarget {
    constructor() {
        super()
        this.shown = false
    }

    canceled() {
        this.hide()
        this.dispatchEvent(new ChooserCancelsEvent())
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

    view(options) {
        return m(".stork-chooser.modal.fade",
                 { tabindex: "-1", role: "dialog",
                   "aria-labelledby": "stork-chooser-title",
                   "aria-hidden": "true" },
                 [
                     m(".modal-dialog", { role: "document" },
                       [ m(".modal-content", [
                           m(".modal-header", [
                               m("h5.modal-title#stork-chooser-title",
                                 options.title),
                               m("button.close",
                                 { type: "button", "data-dismiss": "modal", "aria-label": "Close" },
                                 m("span", {"aria-hidden": "true"}, "×"))
                           ]),
                           m(".modal-body", options.body)
                       ])]),
                 ])
    }
}

export class PersonaChooser extends Chooser {
    constructor (client) {
        super()

        this.client = client
        this.personasLoaded = false

        this.show()
    }

    show() {
        this.personasLoaded = this.client.hasPersonas()
        this.onPersonasLoaded = () => {
            console.log("on personas loaded", this)
            this.personasLoaded = true
            m.redraw()
        }
        this.client.addEventListener('needs-personas', this.onPersonasLoaded)
        super.show()
    }

    hide() {
        this.client.removeEventListener('needs-personas', this.onPersonasLoaded)
        delete this.onPersonasLoaded
        super.hide()
    }

    onchoose ( personaId, creds ) {
        this.dispatchEvent(new PersonaChooserChoosesEvent(this.client, personaId, creds))
    }

    view () {
        var body;

        if ( this.personasLoaded ) {
            if ( this.client.personas.length == 0 ) {
                body = "No personas";
            } else {
                body = m(PersonaList, { chooser: this, candidates: this.client.personas });
            }
        } else {
            body = "Loading..."
        }

        return super.view({ title: "Log-in",
                            body: body })
    }
}

export class ApplianceChooser extends Chooser {
    constructor (client) {
        super()

        this.client = client

        this.show()
    }

    onenter(applianceName) {
        this.deviceName = applianceName
        this.dispatchEvent(new ApplianceChooserChoosesEvent(this.deviceName))
    }

    view () {
        return super.view({ title: "Log-in",
                            body: [
                                m(".input-group", [
                                    m("input.form-control",
                                      { type: "text", placeholder: "Appliance Name",
                                        onkeyup: ({keyCode, target}) => {
                                            if ( keyCode == 13 ) this.onenter(target.value)
                                        },
                                        "aria-label": "Appliance Name" })
                                ])
                            ]})
    }
}

