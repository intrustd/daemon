#ifndef __kite_buffer_H__
#define __kite_buffer_H__

#include "stdlib.h"

// Dynamically allocating buffer
struct buffer {
  size_t b_size, b_bsize;
  char  *b_data;
};

#define buffer_size(b) ((b)->b_size)
#define buffer_data(b, offs) ((b)->b_data + offs)

// Initialize the buffer
void buffer_init(struct buffer *b);

// Finalize the buffer, freeing up internal resources (if any).
//
// If there are no data in the buffer, *data will be NULL. Be sure to check for this.
void buffer_finalize(struct buffer *b, const char **data, size_t *data_sz);
void buffer_finalize_str(struct buffer *b, const char **data);
void buffer_release(struct buffer *b);

// Add more data into the buffer. Returns 0 on success, -1 otherwise (out of memory).
int buffer_write(struct buffer *b, const char *data, size_t sz);

// Expands the buffer by the given size and returns a pointer to the
// start of the region of size sz.
//
// Returns NULL if the buffer could not be expanded
char *buffer_expand(struct buffer *b, size_t sz);

// Returns the number of characters added, or -1 on error
int buffer_printf(struct buffer *b, const char *c, ...)
  __attribute__ ((format (printf, 2, 3)));

int buffer_read_from_file(struct buffer *b, const char *path);

#endif
