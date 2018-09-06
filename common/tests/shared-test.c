#include <assert.h>

#include "../util.h"

int frees_called = 0;
void frees(const struct shared *s, int level) {
  fprintf(stderr, "frees called\n");
  frees_called = 1;
}

int main(int argc, char **argv) {
  struct shared s;

  SHARED_INIT(&s, frees);
  SHARED_DEBUG(&s, "After SHARED_INIT");
  SHARED_REF(&s);
  SHARED_DEBUG(&s, "After SHARED_REF");
  SHARED_REF(&s);
  SHARED_DEBUG(&s, "After SHARED_REF (2)");
  SHARED_WREF(&s);
  SHARED_DEBUG(&s, "After SHARED_WREF");
  SHARED_WREF(&s);
  SHARED_DEBUG(&s, "After SHARED_WREF (2)");
  SHARED_REF(&s);
  SHARED_DEBUG(&s, "After SHARED_REF (3)");
  assert( SHARED_LOCK(&s) == 0 );
  SHARED_DEBUG(&s, "After SHARED_LOCK (4)");
  SHARED_UNREF(&s);
  SHARED_DEBUG(&s, "After SHARED_UNREF (1)");
  SHARED_UNREF(&s);
  SHARED_DEBUG(&s, "After SHARED_UNREF (2)");
  SHARED_UNREF(&s);
  SHARED_DEBUG(&s, "After SHARED_UNREF (3)");
  SHARED_UNREF(&s);
  SHARED_DEBUG(&s, "After SHARED_UNREF (4)");
  SHARED_UNREF(&s);
  SHARED_DEBUG(&s, "After SHARED_UNREF (5)");
  assert(SHARED_LOCK(&s) == -1);
  if ( !frees_called )
    fprintf(stderr, "frees should have been called\n");
  else
    fprintf(stderr, "success\n");
  return 0;
}
