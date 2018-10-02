#include <string.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
 #include <openssl/evp.h>

#include "util.h"
#include "buffer.h"

int parse_hex_str(const char *digest, unsigned char *out, int out_sz) {
  int i = 0;

  for ( i = 0; digest[i] != '\0' && (i / 2) < out_sz; i++ ) {
    int v1, v2;

    v1 = hex_value(digest[i]);
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
  int i = 0;
  for ( i = 0; i < digest_sz; ++i ) {
    sprintf(out + (i * 2), "%02x", digest[i]);
  }
  return out;
}

int parse_decimal(int *out, const char *buf, int buf_sz) {
  int i = 0;

  *out = 0;

  for ( i = 0; i < buf_sz && buf[i] != '\0'; ++i ) {
    int val = dec_value(buf[i]);
    if ( val < 0 ) break;

    *out = *out * 10 + val;
  }

  if ( i == 0 ) return -1;

  return i;
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
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ+/";
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

int format_address(struct sockaddr *sa, socklen_t sa_sz,
                   char *out, size_t out_sz,
                   uint16_t *port) {
  switch ( sa->sa_family ) {
  case AF_INET:
    if ( out_sz >= INET_ADDRSTRLEN && sa_sz >= sizeof(struct sockaddr_in) ) {
      struct sockaddr_in *sin = (struct sockaddr_in *) sa;
      if ( !inet_ntop(AF_INET, &sin->sin_addr, out, out_sz) ) {
        perror("format_address: inet_ntop");
        return -1;
      }
      *port = ntohs(sin->sin_port);
      return 0;
    } else
      return -1;

  case AF_INET6:
    if ( out_sz >= INET6_ADDRSTRLEN && sa_sz >= sizeof(struct sockaddr_in6) ) {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
      if ( !inet_ntop(AF_INET6, &sin6->sin6_addr, out, out_sz) ) {
        perror("format_address: inet_ntop");
        return -1;
      }
      *port = ntohs(sin6->sin6_port);
      return 0;
    } else
      return -1;

  default:
    if ( out_sz > 0 ) {
      out[0] = '\0';
    }
    *port = 0;
    return -1;
  }
}

int parse_address(const char *str, size_t str_sz, uint16_t port,
                  struct sockaddr *sa, socklen_t *sa_sz) {
  char nt_addr[INET6_ADDRSTRLEN];
  struct in_addr in;
  struct in6_addr in6;

  strncpy_safe(nt_addr, str, sizeof(nt_addr));
  fprintf(stderr, "parse_address: %s\n", nt_addr);

  if ( inet_pton(AF_INET, nt_addr, &in.s_addr) ) {
    if ( *sa_sz >= sizeof(struct sockaddr_in) ) {
      struct sockaddr_in *sin = (struct sockaddr_in *) sa;
      *sa_sz = sizeof(*sin);
      sin->sin_family = AF_INET;
      sin->sin_port = htons(port);
      memcpy(&sin->sin_addr, &in, sizeof(sin->sin_addr));
      return 0;
    } else
      return -1;
  }

  STATIC_ASSERT(sizeof(kite_sock_addr) >= sizeof(struct sockaddr_in6), "kite_sock_addr is not big enough");
  fprintf(stderr, "Attempt to parse ipv6 %d\n", inet_pton(AF_INET6, nt_addr, in6.s6_addr));
  if ( inet_pton(AF_INET6, nt_addr, in6.s6_addr) ) {
    if ( *sa_sz >= sizeof(struct sockaddr_in6) ) {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
      *sa_sz = sizeof(*sin6);
      sin6->sin6_family = AF_INET6;
      sin6->sin6_port = htons(port);
      memcpy(&sin6->sin6_addr, &in6, sizeof(sin6->sin6_addr));
      return 0;
    } else
      return -1;
  }

  return -1;
}

void dump_address(FILE *out, void *addr, socklen_t addr_sz) {
  char addr_out[INET6_ADDRSTRLEN];
  uint16_t port;
  if ( format_address(addr, addr_sz, addr_out, sizeof(addr_out), &port) < 0 ) {
    fprintf(out, "<unknown-address>");
  } else
    fprintf(out, "%s:%u", addr_out, port);
}

int kite_sock_addr_equal(kite_sock_addr *ksa, struct sockaddr *a, socklen_t a_sz) {
  if ( a->sa_family == ksa->ksa.sa_family ) {
    switch ( a->sa_family ) {
    case AF_INET6:
      if ( a_sz >= sizeof(ksa->ksa_ipv6) ) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)a;
        return memcmp(a6->sin6_addr.s6_addr, ksa->ksa_ipv6.sin6_addr.s6_addr, 16) == 0 &&
          a6->sin6_port == ksa->ksa_ipv6.sin6_port;
      } else
        return 0;
    case AF_INET:
      if ( a_sz >= sizeof(ksa->ksa_ipv4) ) {
        struct sockaddr_in *a4 = (struct sockaddr_in *)a;
        return a4->sin_addr.s_addr == ksa->ksa_ipv4.sin_addr.s_addr &&
          a4->sin_port == ksa->ksa_ipv4.sin_port;
      } else
        return 0;
      break;

    case AF_UNSPEC:
    default:
      return 0;
    }
  } else
    return 0;
}

#define PRINT_CHAR fprintf(fp, "%02x ", *data); data++
void print_hex_dump_fp(FILE *fp, const unsigned char *data, int data_sz) {
  for ( ; data_sz > 0; data_sz -= 16 ) {
    switch ( (data_sz >= 16) ? 15 : data_sz ) {
    case 15: PRINT_CHAR;
    case 14: PRINT_CHAR;
    case 13: PRINT_CHAR;
    case 12: PRINT_CHAR;
    case 11: PRINT_CHAR;
    case 10: PRINT_CHAR;
    case 9: PRINT_CHAR;
    case 8: PRINT_CHAR;
    case 7: PRINT_CHAR;
    case 6: PRINT_CHAR;
    case 5: PRINT_CHAR;
    case 4: PRINT_CHAR;
    case 3: PRINT_CHAR;
    case 2: PRINT_CHAR;
    case 1: PRINT_CHAR;
    default:
    case 0: PRINT_CHAR; fprintf(fp, "\n");
    }
  }
}

int fread_base64(FILE *sig, void **buf, size_t *buf_len) {
  BIO *b64, *fp;
  int in_len;

  char inbuf[512];

  struct buffer ret;
  buffer_init(&ret);

  b64 = BIO_new(BIO_f_base64());
  if ( !b64 ) return -1;

  fp = BIO_new_fp(sig, BIO_NOCLOSE);
  if ( !fp ) {
    BIO_free_all(b64);
    return -1;
  }

  BIO_push(b64, fp);

  while ( (in_len = BIO_read(b64, inbuf, sizeof(inbuf))) > 0 ) {
    if ( buffer_write(&ret, inbuf, in_len) < 0 ) {
      BIO_free_all(b64);
      buffer_finalize(&ret, (const char **)buf, buf_len);
      if ( *buf ) free(*buf);
      *buf = NULL;
      *buf_len = 0;
      return -1;
    }
  }

  buffer_finalize(&ret, (const char **) buf, buf_len);
  return 0;
}
