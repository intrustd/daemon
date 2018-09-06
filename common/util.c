#include <openssl/rand.h>
#include <openssl/err.h>

#include "util.h"

int parse_hex_str(const char *digest, unsigned char *out, int out_sz) {
  int i = 0;

  for ( i = 0; digest[i] != '\0' && (i / 2) < out_sz; i++ ) {
    int v1, v2;

    v1 = hex_value(digest[i]), v2;
    if ( v1 < 0 ) return -1;

    // Next character in octet
    i++;
    if ( digest[i] == '\0' ) {
      // Break in middle of octet, return error
      return -1;
    }
    v2 = hex_value(digest[i]);
    if ( v2 < 0 ) return -1;

    out[i / 2] = (v1 << 4) | v2;
  }

  return (i / 2);
}

char *hex_digest_str(const unsigned char *digest, char *out, int digest_sz) {
  int i = 0, ofs;
  for ( i = 0; i < digest_sz; ++i ) {
    sprintf(out + (i * 2), "%02x", digest[i]);
  }
  return out;
}

void find_newline(const char *buf, int buf_sz, int *next_newline, int *nl_length) {
  int i = 0;

  while ( 1 ) {
    for ( ; i < buf_sz && buf[i] != '\r' && buf[i] != '\n'; ++i );

    if ( i >= buf_sz ) {
      *next_newline = -1;
      *nl_length = 0;
      return;
    }

    if ( buf[i] == '\n' ) {
      *next_newline = i;
      *nl_length = 1;
      return;
    }

    if ( buf[i] == '\r' && (i + 1) < buf_sz && buf[i + 1] == '\n' ) {
      *next_newline = i;
      *nl_length = 2;
      return;
    }

    if ( buf[i] == '\r' )
      i++;
  }
}

int b64_encode(const unsigned char *din, size_t din_sz,
               char *out, size_t *out_sz) {
  static int mod_table[] = {0, 2, 1};

  static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                  'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                  '4', '5', '6', '7', '8', '9', '+', '/'};

  size_t exp_out_sz = 4 * ((din_sz + 2) / 3);
  int i, j;

  if ( exp_out_sz > *out_sz ) {
    *out_sz = 0;
    return -1;
  }

  *out_sz = exp_out_sz;

  for (i = 0, j = 0; i < din_sz; ) {
    uint32_t octet_a = i < din_sz ? (unsigned char)din[i++] : 0;
    uint32_t octet_b = i < din_sz ? (unsigned char)din[i++] : 0;
    uint32_t octet_c = i < din_sz ? (unsigned char)din[i++] : 0;

    uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

    out[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
    out[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
    out[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
    out[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
  }

  for (i = 0; i < mod_table[din_sz % 3]; i++)
    out[*out_sz - 1 - i] = '=';

  return 0;
}

int uri_decode(const char *url, size_t url_sz,
               char *out, size_t out_sz) {
  size_t i = 0, j = 0;

  for ( i = 0; i < url_sz; i++ ) {
    if ( j >= out_sz ) return -1;

    if ( url[i] == '%' ) {
      if ( (i + 2) < url_sz &&
           hex_value(url[i + 1]) >= 0 && hex_value(url[i + 2]) >= 0 ) {
        uint8_t cout = hex_value(url[i + 1]) * 0x10 +
          hex_value(url[i + 2]);
        out[j++] = cout;
        i += 2;
      } else
        return -1;
    } else
      out[j++] = url[i];
  }

  if ( j < out_sz ) {
    out[j] = '\0';
    return 0;
  } else
    return -1;
}

int atoi_ex(char *s, char *e, int *out) {
  int err;
  *out = 0;

  for ( ; s != e; ++s ) {
    err = dec_value(*s);
    if ( err < 0 ) { *out = 0; return -1; }

    *out = (*out) * 10 + err;
  }

  return 0;
}

int random_printable_string(char *out, size_t out_sz) {
  static const char readable_chars[] =
    "0123456789abcdefghcijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*(){}[]~`<>.,";
  size_t i;
  int ix;

  for ( i = 0; i < out_sz; ++i ) {
    if ( !RAND_bytes((unsigned char *) &ix, sizeof(ix)) ) {
      fprintf(stderr, "random_printable_string: RAND_bytes failed\n");
      ERR_print_errors_fp(stderr);
      return 0;
    }

    ix %= (sizeof(readable_chars) - 1);
    out[i] = readable_chars[ix];
  }

  return 1;
}
