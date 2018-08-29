#include "appliance.h"

void applianceinfo_clear(struct applianceinfo *info) {
  memset(info, 0, sizeof(struct applianceinfo));
}
