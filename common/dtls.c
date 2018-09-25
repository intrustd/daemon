#include <string.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "dtls.h"

// TODO test this

void dtlscookies_clear(struct dtlscookies *cs) {
  cs->dc_refresh_interval = cs->dc_max_age = cs->dc_cookie_length
    = cs->dc_total_cookies = 0;
  memset(&cs->dc_last_cookie, 0, sizeof(cs->dc_last_cookie));
  cs->dc_cookie_data = NULL;
}

void dtlscookies_release(struct dtlscookies *cs) {
  if ( cs->dc_cookie_data ) {
    free(cs->dc_cookie_data);
  }
  dtlscookies_clear(cs);
}

int dtlscookies_init(struct dtlscookies *cs, int refresh_interval,
                     int max_age, int cookie_length) {
  if ( refresh_interval <= 0 ) return -1;
  if ( max_age < refresh_interval ) return -1;

  cs->dc_refresh_interval = refresh_interval;
  cs->dc_max_age = max_age;
  cs->dc_cookie_length = cookie_length;
  cs->dc_total_cookies = 0;

  cs->dc_cookie_data = malloc(DC_MAX_COOKIE_STORAGE(cs));
  if ( !cs->dc_cookie_data ) {
    fprintf(stderr, "dtlscookies_init: no space\n");
    return -1;
  }

  memset(cs->dc_cookie_data, 0, DC_MAX_COOKIE_STORAGE(cs));

  return 0;
}

static int dtlscookies_cookie_is_valid(struct dtlscookies *cs, int ix) {
  int i = 0;

  if ( ix < 0 || ix >= cs->dc_total_cookies ) return 0;

  for ( i = 0; i < cs->dc_cookie_length; ++i ) {
    if ( cs->dc_cookie_data[cs->dc_cookie_length * ix + i] != '\0' )
      return 1;
  }

  return 0;
}

int dtlscookies_generate_cookie(struct dtlscookies *cs, unsigned char *cookie,
                                unsigned int *cookie_len) {
  struct timespec now;
  int cookie_time, last_cookie_time, cookies_to_shift, cookies_to_copy;

  if ( *cookie_len < cs->dc_cookie_length )
    return -1;

  if ( clock_gettime(CLOCK_REALTIME, &now) < 0 ) {
    perror("dtlscookies_generate_cookie: clock_gettime");
    return -1;
  }

  if ( now.tv_sec < cs->dc_last_cookie.tv_sec ) {
    // Now is less than last
    fprintf(stderr, "dtlscookies_generate_cookie: time skew detected\n");
    return -1;
  }

  // Now attempt to find the timestamp of the cookie expected
  cookie_time = (now.tv_sec / cs->dc_refresh_interval) * cs->dc_refresh_interval;
  last_cookie_time = (cs->dc_last_cookie.tv_sec / cs->dc_refresh_interval) * cs->dc_refresh_interval;

  cookies_to_shift = (cookie_time - last_cookie_time) / cs->dc_refresh_interval;

  // Shift the cookies this many times
  cookies_to_copy = DC_MAX_COOKIE_COUNT(cs) - cookies_to_shift;
  if ( cookies_to_copy < 0 )
    cookies_to_copy = 0;

  memcpy(cs->dc_cookie_data + (cs->dc_cookie_length * cookies_to_shift),
         cs->dc_cookie_data, (cs->dc_cookie_length * cookies_to_copy));

  if ( cookies_to_shift > DC_MAX_COOKIE_COUNT(cs) )
    cookies_to_shift = DC_MAX_COOKIE_COUNT(cs);
  memset(cs->dc_cookie_data, 0, cs->dc_cookie_length * cookies_to_shift);

  cs->dc_total_cookies += cookies_to_shift;
  if ( cs->dc_total_cookies > DC_MAX_COOKIE_COUNT(cs) )
    cs->dc_total_cookies = DC_MAX_COOKIE_COUNT(cs);

  if ( cookies_to_shift > 0 ) {
    // We need to generate a new cookie
    while ( !dtlscookies_cookie_is_valid(cs, 0) ) {
      if ( !RAND_bytes((unsigned char *)cs->dc_cookie_data, cs->dc_cookie_length) ) {
        fprintf(stderr, "RAND_bytes failed\n");
        ERR_print_errors_fp(stderr);
      }
    }
  }

  *cookie_len = cs->dc_cookie_length;
  memcpy(cookie, cs->dc_cookie_data, cs->dc_cookie_length);

  return 0;
}

int dtlscookies_verify_cookie(struct dtlscookies *cs, const unsigned char *cookie,
                              unsigned int cookie_len) {
  int i;

  if ( cookie_len != cs->dc_cookie_length ) return 0;

  for ( i = 0; i < cs->dc_total_cookies; ++i ) {
    if ( dtlscookies_cookie_is_valid(cs, i) ) {
      if ( memcmp(cs->dc_cookie_data + i * cs->dc_cookie_length,
                  cookie, cookie_len) == 0 ) return 1;
    }
  }

  return 0;
}
