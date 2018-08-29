#ifndef __flock_websocket_H__
#define __flock_websocket_H__

#include "event.h"

#define WS_EVENT_ACCEPT EVT_CTL_CUSTOM

void websocket_fn(struct eventloop *el, int op, void *arg);

#endif
