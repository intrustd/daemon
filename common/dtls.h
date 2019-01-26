#ifndef __intrustd_dtls_H__
#define __intrustd_dtls_H__

// Provides a time-based SSL generate cookie callback and verification
// function for use with DTLS. You will need to use a mutex to force
// synchronization

struct dtlscookies {
  // Seconds after which to expire a cookie
  int dc_refresh_interval;

  // The maximum age (in seconds) of a cookie to accept
  int dc_max_age;

  // How long each cookie should be
  int dc_cookie_length;

  // The number of cookies we have stored right now
  int dc_total_cookies;

  struct timespec dc_last_cookie;

  char *dc_cookie_data;
};

#define DC_MAX_COOKIE_COUNT(dc) ((((dc)->dc_max_age + (dc)->dc_refresh_interval - 1) / (dc)->dc_refresh_interval) * (dc)->dc_refresh_interval)
#define DC_MAX_COOKIE_STORAGE(dc) (DC_MAX_COOKIE_COUNT(dc) * (dc)->dc_cookie_length)

void dtlscookies_clear(struct dtlscookies *cs);
void dtlscookies_release(struct dtlscookies *cs);
int dtlscookies_init(struct dtlscookies *cs,
                     int refresh_interval,
                     int max_age,
                     int cookie_length);
// Returns 0 on success, negative on error
int dtlscookies_generate_cookie(struct dtlscookies *cs, unsigned char *cookie,
                                unsigned int *cookie_len);
// Returns 0 on failure, 1 on success, negative on error
int dtlscookies_verify_cookie(struct dtlscookies *cs, const unsigned char *cookie,
                              unsigned int cookie_len);

#endif
