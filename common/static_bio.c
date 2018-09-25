#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/bio.h>

#include "util.h"

// #define BIO_STATIC_DEBUG
#ifdef BIO_STATIC_DEBUG
#define dbg_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define dbg_printf(...) (void) 0
#endif

static BIO_METHOD *static_bio_meth = NULL;

static int static_bio_write(BIO *bio, const char *in, int sz) {
  struct BIO_static *data = (struct BIO_static *) BIO_get_data(bio);
  ssize_t bytes_left;
  assert(data);

  dbg_printf("static bio write\n");
  if ( !BIO_STATIC_IS_WRITE(data) ) return -2;
  dbg_printf("static write %d\n", sz);

  bytes_left = BIO_STATIC_SIZE(data) - BIO_STATIC_OFS(data);
  assert(bytes_left >= 0);

  if ( sz < bytes_left )
    bytes_left = sz;

  if ( bytes_left )
    memcpy(BIO_STATIC_CUR(data), in, bytes_left);

  if ( sz > bytes_left ) {
    BIO_set_retry_write(bio);
  } else
    BIO_clear_retry_flags(bio);

  data->bs_ptr += bytes_left;

  dbg_printf("static write returns %ld\n", bytes_left);

  return bytes_left;
}

static int static_bio_read(BIO *bio, char *out, int outsz) {
  struct BIO_static *data = (struct BIO_static *) BIO_get_data(bio);
  ssize_t bytes_left;
  assert(data);

  dbg_printf("static bio read\n");
  if ( !BIO_STATIC_IS_READ(data) ) return -2;

  if ( data->bs_ptr == -2 ) {
    BIO_set_retry_read(bio);
    return 0;
  }

  bytes_left = BIO_STATIC_SIZE(data) - BIO_STATIC_OFS(data);
  dbg_printf("static bio read: bytes %ld %ld %d\n", bytes_left, data->bs_ptr, BIO_STATIC_IS_PEEKING(data));
  if ( bytes_left == 0 ) {
    BIO_set_retry_read(bio);
    return 0;
  } else {
    if ( bytes_left > outsz )
      bytes_left = outsz;

    BIO_clear_retry_flags(bio);

    memcpy(out, BIO_STATIC_CUR(data), bytes_left);

    if ( !BIO_STATIC_IS_PEEKING(data) )
      data->bs_ptr += bytes_left;

    dbg_printf("static bio after read: (ispeeking=%d) %ld of %ld read\n",
               BIO_STATIC_IS_PEEKING(data), BIO_STATIC_OFS(data), BIO_STATIC_SIZE(data));

    return bytes_left;
  }
}

static long static_bio_ctrl(BIO *bio, int op, long larg, void *parg) {
  struct BIO_static *data = (struct BIO_static *) BIO_get_data(bio);
  assert(data);

  dbg_printf("bio ctrl %d\n", op);

  switch ( op ) {
  case BIO_CTRL_RESET:
    data->bs_ptr = 0;
    BIO_clear_retry_flags(bio);
    return 1;
  case BIO_CTRL_DGRAM_QUERY_MTU:
    return 1500;
  case BIO_CTRL_WPENDING:
    if ( BIO_STATIC_IS_WRITE(data) )
      return data->bs_ptr;
  case BIO_CTRL_FLUSH:
    if ( data->bs_ptr == 0 ) {
      dbg_printf("No need to flush\n");
      return 1;
    } else {
      BIO_set_retry_special(bio);
      return -1;
    }
  case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
    return 128;
  case BIO_CTRL_DGRAM_SET_PEEK_MODE:
  case BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE:
    if ( larg ) {
      if ( (BIO_STATIC_SIZE(data) - BIO_STATIC_OFS(data)) == 0 )
        data->bs_ptr = -2;
      else
        data->bs_ptr = -1;
    } else {
      if ( data->bs_ptr == -1 )
        data->bs_ptr = 0;
      else
        data->bs_ptr = labs(data->bs_sz);
    }
    return 0;
  default:
    dbg_printf("Unknown bio type %d\n", op);
    return -2;
  }
}

void init_static_bio() {
  int new_idx = BIO_get_new_index();

  static_bio_meth = BIO_meth_new(new_idx, "Flockd static bio");
  if ( !static_bio_meth ) {
    fprintf(stderr, "init_static_bio: out of memory\n");
    exit(2);
  }

  BIO_meth_set_write(static_bio_meth, static_bio_write);
  BIO_meth_set_read(static_bio_meth, static_bio_read);
  //  BIO_meth_set_puts(static_bio_meth, static_bio_puts);
  //  BIO_meth_set_gets(static_bio_meth, static_bio_gets);
  BIO_meth_set_ctrl(static_bio_meth, static_bio_ctrl);
}

BIO *BIO_new_static(int mode, struct BIO_static *st) {
  BIO *bio;

  assert(static_bio_meth);

  bio = BIO_new(static_bio_meth);
  if ( !bio )
    return NULL;

  if ( mode < 0 ) { // Write
    st->bs_sz = -BIO_STATIC_SIZE(st);
  }

  BIO_set_data(bio, st);
  BIO_set_init(bio, 1);

  return bio;
}

void BIO_static_set(BIO *bio, struct BIO_static *st) {
  BIO_set_data(bio, st);
}
