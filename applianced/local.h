#ifndef __appliance_local_H__
#define __appliance_local_H__

#include "local_proto.h"
#include "state.h"

struct localapi;

struct localapi *localapi_alloc(struct appstate *as, int sk);

#endif
