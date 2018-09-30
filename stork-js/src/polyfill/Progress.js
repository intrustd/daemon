import nprogress from 'nprogress';

import 'nprogress/nprogress.css';

nprogress.configure({trickle: false})

class SubTracker {
    constructor(tkr, max, total) {
        this.tracker = tkr
        this.max = max
        this.parentTotal = total

        this.complete = 0
        this.total = 0
    }

    setProgress(complete, total) {
        this.complete = complete
        this.total = total

        this.tracker.setProgress(this.max * (this.complete / this.total),
                                 this.total)
    }

    done() {
        if ( this.max == this.parentTotal )
            this.tracker.done()
    }
}

class ProgressTracker {
    constructor(mgr, reqId) {
        this.reqId = reqId
        this.mgr = mgr
        this.total = 0
        this.complete = 0
    }

    setProgress(complete, total) {
        this.total = total
        this.complete = complete
        this.mgr.setProgress(this.reqId, complete, total)
    }

    done() {
        this.mgr.signalDone(this.reqId)
    }

    subtracker(max, total) {
        return new SubTracker(this, max, total)
    }
}

class ProgressManager {
    constructor() {
        this.currentReqId = 0
        this.current = {}
        this.shown = false
    }

    startFetch() {
        var ret = new ProgressTracker(this, this.currentReqId)

        this.current[this.currentReqId] = { complete: 0, total: 0 }
        this.currentReqId += 1

        this.updateBar()

        return ret
    }

    signalDone(reqId) {
        delete this.current[reqId]
        this.updateBar()
    }

    setProgress(reqId, complete, total) {
        this.current[reqId] = { complete, total }

        this.updateBar()
    }

    updateBar() {
        var shouldShow = Object.keys(this.current).length > 0;
        if ( shouldShow && !this.shown ) {
            this.shown = true
            nprogress.start();
        } else if ( !shouldShow && this.shown ) {
            this.shown = false;
            nprogress.done();
        }

        if ( shouldShow ) {
            var total = 0
            var complete = 0
            for ( var reqId in this.current ) {
                var req = this.current[reqId]
                total += req.total
                complete += req.complete
            }

            nprogress.set(complete / total)
        }
    }
}

var GlobalProgressManager = new ProgressManager()
export default GlobalProgressManager
