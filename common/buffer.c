#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

#include "util.h"
#include "buffer.h"

#define INITBUFSZ 32

void buffer_init(struct buffer *b) {
  b->b_bsize = b->b_size = 0;
  b->b_data = NULL;
}

void buffer_finalize(struct buffer *b, const char **data, size_t *data_sz) {
  if ( b->b_data ) {
    b->b_data = realloc(b->b_data, b->b_size);

    *data    = b->b_data;
    *data_sz = b->b_size;

    b->b_data = NULL;
    b->b_size = b->b_bsize = 0;
  } else {
    *data = NULL;
    *data_sz = 0;
  }
}

void buffer_finalize_str(struct buffer *b, const char **d) {
  static const char null_char[1] = { 0 };
  size_t sz;
  buffer_write(b, null_char, 1);
  buffer_finalize(b, d, &sz);
}

void buffer_release(struct buffer *b) {
  if ( b->b_data )
    free(b->b_data);

  b->b_data = NULL;
  b->b_bsize = 0;
  b->b_size = 0;
}

int buffer_write(struct buffer *b, const char *data, size_t sz) {
  char *buf = buffer_expand(b, sz);
  if ( !buf ) return -1;

  memcpy(buf, data, sz);

  return 0;
}

char *buffer_expand(struct buffer *b, size_t sz) {
  char *ptr;

  while ( (b->b_size + sz) > b->b_bsize ) {
    char *new_data;
    size_t new_size;

    if ( b->b_bsize == 0 ) new_size = INITBUFSZ;
    else new_size = b->b_bsize * 2;

    new_data = realloc(b->b_data, new_size);
    if ( !new_data ) return NULL;

    b->b_data = new_data;
    b->b_bsize = new_size;
  }

  ptr = b->b_data + b->b_size;
  b->b_size += sz;

  return ptr;
}

int buffer_printf(struct buffer *b, const char *fmt, ...) {
  char *buf;
  va_list vl1, vl2;
  int sz;

  va_start(vl1, fmt);
  va_copy(vl2, vl1);

  sz = vsnprintf(NULL, 0, fmt, vl1);
  buf = buffer_expand(b, sz + 1);
  if ( !buf ) {
    sz = -1;
  } else {
    SAFE_ASSERT( vsnprintf(buf, sz + 1, fmt, vl2) == sz );
    b->b_size -= 1;
  }

  va_end(vl1);
  va_end(vl2);

  return sz;
}

int buffer_read_from_file(struct buffer *b, const char *path) {
  int ret;
  FILE *fp = fopen(path, "rb");
  if ( !fp ) return -1;

  ret = buffer_read_from_file_ex(b, fp);

  fclose(fp);

  return ret;
}

int buffer_read_from_file_ex(struct buffer *b, FILE *fp) {
  char chunk[1024];
  size_t sz;

  buffer_init(b);

  while ( (sz = fread(chunk, 1, sizeof(chunk), fp)) ) {
    buffer_write(b, chunk, sz);
  }

  return 0;
}
