#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <dirent.h>
#define flock __unused_flock
#include <fcntl.h>
#undef flock
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

#include "util.h"
#include "state.h"
#include "local.h"
#include "buffer.h"
#include "pconn.h"
#include "update.h"
#include "token.h"

#define OP_APPSTATE_ACCEPT_LOCAL EVT_CTL_CUSTOM
#define OP_APPSTATE_SAVE_FLOCK   (EVT_CTL_CUSTOM + 1)
#define OP_APPSTATE_APPLICATION_UPDATED (EVT_CTL_CUSTOM + 2)
#define OP_APPSTATE_AUTOSTART_APPS (EVT_CTL_CUSTOM + 3)

#define FLOCKS_PATH_TEMPLATE "%s/flocks"
#define APPS_PATH_TEMPLATE "%s/apps"
#define TMP_APPS_PATH_TEMPLATE "%s/.apps.tmp"

#define ADMIN_APP_URL "admin.intrustd.com"

int g_openssl_appstate_ix;
int g_openssl_flock_data_ix;
int g_openssl_pconn_data_ix;

static const unsigned char intrustd_alpn_protos[] =
  { 6, 'w', 'e', 'b', 'r', 't', 'c'
};

static int appstate_certificate_digest(X509 *cert, unsigned char *digest) {
  EVP_PKEY *pubkey = NULL;
  unsigned char *pubkey_raw = NULL;
  int err;

  pubkey = X509_get0_pubkey(cert);
  cert = NULL;
  if ( !pubkey ) {
    fprintf(stderr, "appstate_certificate_digest: No public key in SSL certificate\n");
    return -1;
  }

  err = i2d_PublicKey(pubkey, &pubkey_raw);
  if ( err < 0 ) {
    fprintf(stderr, "appstate_certificate_digest: Could not write public key in DER format\n");
    EVP_PKEY_free(pubkey);
    return -1;
  }

  assert(pubkey_raw);
  FLOCK_SIGNATURE_METHOD(pubkey_raw, err, digest);

  free(pubkey_raw);

  return 0;
}

static int appstate_alpn_select_callback(SSL *ssl, const unsigned char **out,
                                         unsigned char *outlen,
                                         const unsigned char *in,
                                         unsigned int inlen,
                                         void *arg) {
  int success;
  fprintf(stderr, "Got ALPN protos %.*s\n", inlen, in);
  success =  SSL_select_next_proto((unsigned char **)out, outlen, in, inlen,
                                   intrustd_alpn_protos, sizeof(intrustd_alpn_protos));
  if ( success )
    return SSL_TLSEXT_ERR_OK;
  else
    return SSL_TLSEXT_ERR_NOACK;
}

static int appstate_verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
  X509 *cert;
  SSL *ssl;
  int err, depth;

  struct flock *f;
  struct pconn *pc;


  cert = X509_STORE_CTX_get_current_cert(ctx);
  err = X509_STORE_CTX_get_error(ctx);
  depth = X509_STORE_CTX_get_error_depth(ctx);

  ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());

  if ( !preverify_ok ) {
    int cert_err = X509_STORE_CTX_get_error(ctx);

    if ( cert_err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT )
      preverify_ok = 1;
    else {
      fprintf(stderr, "appstate_verify_callback: cert fails preverification because: %s\n",
              X509_verify_cert_error_string(cert_err));
    }
  }

  if ( depth > FLOCK_MAX_CERT_DEPTH )
    return 0;

  f = SSL_get_flock(ssl);
  if ( f ) {
    if ( f->f_flags & FLOCK_FLAG_FORCE_ACCEPT )
      return 1;

    if ( f->f_flags & FLOCK_FLAG_VALIDATE_CERT ) {
      unsigned char digest_out[sizeof(f->f_expected_digest)];
      // Check the certificate signature
      err = appstate_certificate_digest(cert, digest_out);
      if ( err < 0 ) {
        fprintf(stderr, "appstate_verify_callback: could not calculate certificate digest\n");
        return 0;
      }

      if ( memcmp(digest_out, f->f_expected_digest, sizeof(digest_out)) == 0 ) {
        return 1;
      } else {
        char digest_str[sizeof(digest_out)*2];
        fprintf(stderr, "appstate_verify_callback: verification failed\n");
        fprintf(stderr, "     Got %s\n", hex_digest_str(digest_out, digest_str, sizeof(digest_out)));
        fprintf(stderr, "Expected %s\n", hex_digest_str(f->f_expected_digest, digest_str, sizeof(digest_out)));
        return 0;
      }
    }

    if ( f->f_flags & FLOCK_FLAG_PENDING ) {
      // New certificate
      return preverify_ok;
    }

    return 0;
  }

  pc = SSL_get_pconn(ssl);
  if ( pc ) {
    if ( pc->pc_answer_flags & PCONN_ANSWER_HAS_FINGERPRINT ) {
      if ( pc->pc_remote_cert_fingerprint_digest &&
           EVP_MD_size(pc->pc_remote_cert_fingerprint_digest) <= sizeof(pc->pc_remote_cert_fingerprint) )  {
        int digest_size = EVP_MD_size(pc->pc_remote_cert_fingerprint_digest);
        unsigned char exp_digest[digest_size];
        unsigned int exp_digest_len = digest_size;

        if ( !X509_digest(cert, pc->pc_remote_cert_fingerprint_digest, exp_digest, &exp_digest_len) ) {
          fprintf(stderr, "appstate_verify_callback(pconn): could not calculate digest\n");
          return 0;
        }

        if ( exp_digest_len != digest_size ) {
          fprintf(stderr, "appstate_verify_callback(pconn): mismatch digest len\n");
          return 0;
        }

        if ( memcmp(exp_digest, pc->pc_remote_cert_fingerprint, digest_size) == 0 ) {
          return 1;
        } else {
          fprintf(stderr, "appstate_verify_callback (pconn): fingerprint verification failed for pconn\n");
          return 0;
        }
      } else {
        fprintf(stderr, "appstate_verify_callback(pconn): invalid fingerprint type\n");
        return 0;
      }
    } else {
      fprintf(stderr, "appstate_verify_callback(pconn): pconn has no fingerprint\n");
      return 0;
    }
  }

  fprintf(stderr, "appstate_verify_callback: unsure how to handle verification\n");
  return 0;
}

static int appstate_update_app(struct appstate *st, const char *app_id,
                               struct appmanifest *cur_mf, struct appmanifest *mf,
                               int do_add) {
  char apps_path[PATH_MAX], tmp_path[PATH_MAX];
  char apps_line[1024];
  FILE *apps, *tmp;

  int err, did_update = 0;

  char dbg_digest_str1[SHA256_DIGEST_LENGTH * 2 + 1];
  char dbg_digest_str2[SHA256_DIGEST_LENGTH * 2 + 1];

  err = snprintf(apps_path, sizeof(apps_path), APPS_PATH_TEMPLATE, st->as_conf_dir);
  if ( err >= sizeof(apps_path) ) {
    fprintf(stderr, "appstate_update_app: path buffer overflow\n");
    return -1;
  }

  err = snprintf(tmp_path, sizeof(tmp_path), TMP_APPS_PATH_TEMPLATE, st->as_conf_dir);
  if ( err >= sizeof(tmp_path) ) {
    fprintf(stderr, "appstate_update_app: path buffer overflow\n");
    return -1;
  }

  apps = fopen(apps_path, "rt");
  if ( !apps ) {
    fprintf(stderr, "appstate_update_app: could not open %s\n", apps_path);
    return -1;
  }

  tmp = fopen(tmp_path, "wt");
  if ( !tmp ) {
    fprintf(stderr, "appstate_update_app: could not open %s\n", tmp_path);
    fclose(apps);
    return -1;
  }

  if ( cur_mf ) {
    fprintf(stderr, "upgrade %s from %s to %s\n",
            app_id,
            hex_digest_str(cur_mf->am_digest, dbg_digest_str1, sizeof(cur_mf->am_digest)),
            hex_digest_str(mf->am_digest, dbg_digest_str2, sizeof(mf->am_digest)));
  } else {
    fprintf(stderr, "install %s from %s\n",
            app_id,
            hex_digest_str(mf->am_digest, dbg_digest_str2, sizeof(mf->am_digest)));
  }

  while ( fgets(apps_line, sizeof(apps_line), apps) ) {
    int line_length = strlen(apps_line);
    if ( line_length == 0 ) continue;

    if ( apps_line[line_length - 1] == '\n' || feof(apps) ) {
      char apps_url[1024], mf_digest_str[SHA256_DIGEST_LENGTH * 2 + 1];
      err = sscanf(apps_line, "%s %64s", apps_url, mf_digest_str);
      if ( err != 2 ) goto error;

      if ( strcmp(apps_url, app_id) == 0 ) {
        if ( did_update ) {
          fprintf(stderr, "appstate_update_app: duplicate app entry\n");
          goto error;
        } else {
          fprintf(stderr, "Doing update\n");
          hex_digest_str(mf->am_digest, mf_digest_str, sizeof(mf->am_digest));
          did_update = 1;
        }
      }

      fprintf(tmp, "%s %s\n", apps_url, mf_digest_str);
    } else {
      goto error;
    }

    continue;

  error:
    fclose(apps);
    fclose(tmp);
    unlink(tmp_path);
    fprintf(stderr, "appstate_update_app: could not add app to appliance: line overflow\n");
    return -1;
  }

  if ( !did_update && do_add ) {
    char mf_digest_str[SHA256_DIGEST_LENGTH * 2 + 1];
    fprintf(tmp, "%s %s\n", app_id, hex_digest_str(mf->am_digest, mf_digest_str, sizeof(mf->am_digest)));

    did_update = 1;
  }

  fclose(apps);
  fclose(tmp);

  if ( did_update ) {
    rename(tmp_path, apps_path);
    return 0;
  } else {
    fprintf(stderr, "appstate_update_app: did not update\n");
    return -1;
  }
}

static void appstate_add_flock(struct appstate *st, char *flock_line) {
  char flocks_path[PATH_MAX];
  FILE *flocks;

  int err;

  err = snprintf(flocks_path, sizeof(flocks_path), FLOCKS_PATH_TEMPLATE, st->as_conf_dir);
  if ( err >= sizeof(flocks_path) ) {
    fprintf(stderr, "appstate_add_flock: path buffer overflow\n");
    return;
  }

  flocks = fopen(flocks_path, "at+");
  fprintf(flocks, "%s", flock_line);
  fclose(flocks);
}

// Must hold the flock mutex
static int appstate_format_flock_line(struct flock *flock, char *out, int out_sz, unsigned char *digest_out) {
  X509 *peer_cert;
  int err, i;

  if ( !(flock->f_flock_state > FLOCK_STATE_PENDING && flock->f_flock_state < FLOCK_STATE_SUSPENDED) ) {
    fprintf(stderr, "appstate_format_flock_line: ignoring flock because it is not connected\n");
    return -1;
  }

  if ( flock->f_flags & FLOCK_FLAG_INSECURE ) {
    memset(digest_out, 0, FLOCK_SIGNATURE_DIGEST_SZ);
  } else {

    peer_cert = SSL_get_peer_certificate(flock->f_dtls_client);
    if ( !peer_cert ) {
      fprintf(stderr, "appstate_format_flock_line: No peer certificate in DTLS object\n");
      return -1;
    }

    err = appstate_certificate_digest(peer_cert, digest_out);
    X509_free(peer_cert);
    if ( err < 0 ) {
      fprintf(stderr, "appstate_format_flock_line: Could not calculate certificate digest\n");
      return -1;
    }
  }

  err = snprintf(out, out_sz, "%s ", flock->f_uri_str);
  for ( i = 0; i < FLOCK_SIGNATURE_DIGEST_SZ; ++i ) {
    err += snprintf(out + err, out_sz - err, "%02x", digest_out[i]);

    if ( err > out_sz ) break;
  }
  if ( err > out_sz ) {
    return -1;
  } else {
    err += snprintf(out + err, out_sz - err, "\n");

    if ( err > out_sz ) return -1;
    else return 0;
  }
}

static int appstate_open_keys(struct appstate *as, struct appconf *ac) {
  FILE *fp;
  char app_key_nm[PATH_MAX];
  int err;
  ASN1_TIME *t;
  time_t now;
  X509_NAME *name;

  err = snprintf(app_key_nm, sizeof(app_key_nm), "%s/key.pem", ac->ac_conf_dir);
  if ( err < 0 || err >= sizeof(app_key_nm) ) {
    perror("appstate_open_keys: snprintf");
    exit(1);
  }

  fp = fopen(app_key_nm, "rt");
  if ( !fp ) {
    perror("appstate_open_keys: fopen");
    fprintf(stderr, "Could not open the key file %s. Run the command\n\n", app_key_nm);
    fprintf(stderr, "   openssl ecparam -out %s.ecparam -name prime256v1\n", app_key_nm);
    fprintf(stderr, "   openssl genpkey -paramfile %s.ecparam -out %s\n", app_key_nm, app_key_nm);
    fprintf(stderr, "to generate a private key\n");
    exit(1);
  }

  as->as_privkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  if ( !as->as_privkey ) goto openssl_error;

  fclose(fp);

  // Now let's try to create a X509 certificate
  as->as_cert = X509_new();
  if ( !as->as_cert ) goto openssl_error;

  if ( !ASN1_INTEGER_set(X509_get_serialNumber(as->as_cert), 1) ) goto openssl_error;

  time(&now);
  t = ASN1_TIME_set(NULL, now);
  X509_set_notBefore(as->as_cert, t);

  now += 3600 * 24 * 365 * 10; // 10 years
  t = ASN1_TIME_set(t, now);
  X509_set_notAfter(as->as_cert, t);
  ASN1_STRING_free(t);
  t = NULL;

  if ( !X509_set_pubkey(as->as_cert, as->as_privkey) ) goto openssl_error;

  name = X509_get_subject_name(as->as_cert);
  if ( !name ) goto openssl_error;

  err = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"WebRTC", -1, -1, 0);
  if ( !err ) goto openssl_error;

  if ( !X509_set_issuer_name(as->as_cert, name) ) goto openssl_error;

  if ( !X509_sign(as->as_cert, as->as_privkey, EVP_sha256()) ) goto openssl_error;

  return 0;

 openssl_error:
    ERR_print_errors_fp(stderr);
    exit(1);
}

static int appstate_generate_name(struct appstate *as) {
  static const char *words[] = {
    #include "words.h"
  };

  int name_components[4];
  int i, j, ix, sz = 0;

  for ( i = 0; i < sizeof(name_components) / sizeof(name_components[0]); ++i ) {
    int word_sz;

    SAFE_ASSERT(RAND_bytes((unsigned char *)&ix, sizeof(ix)));

  try_again:
    ix %= sizeof(words) / sizeof(words[0]);

    for ( j = 0; j < i; ++j )
      if (name_components[j] == ix) goto try_again;

    name_components[i] = ix;

    word_sz = strlen(words[ix]);
    if ( i != 0 )
      word_sz += 1;

    if ( (sz + word_sz) >= sizeof(as->as_appliance_name) ) {
      fprintf(stderr, "Internal error: appliance name would cause overflow\n");
      return -1;
    }
    if ( i != 0 ) as->as_appliance_name[sz] = ' ';
    memcpy(as->as_appliance_name + sz + (i != 0 ? 1 : 0),
           words[ix],
           word_sz - (i != 0 ? 1 : 0));
    sz += word_sz;
    as->as_appliance_name[sz] = '\0';
  }

  return 0;
}

static int appstate_open_name(struct appstate *as, struct appconf *ac) {
  char name_file_path[PATH_MAX];
  FILE *name_file_fp;
  int err;

  err = snprintf(name_file_path, sizeof(name_file_path), "%s/name", ac->ac_conf_dir);
  if ( err < 0 || err >= sizeof(name_file_path) ) {
    perror("appstate_open_name: snprintf");
    return -1;
  }

  name_file_fp = fopen(name_file_path, "rt");
  if ( !name_file_fp ) {
    int err = errno;
    if ( err == ENOENT ) {
      fprintf(stderr, "Generating an appliance name\n");
      if ( appstate_generate_name(as) < 0 ) return -1;

      name_file_fp = fopen(name_file_path, "wt");
      if ( !name_file_fp ) {
        perror("appstate_open_name: fopen");
        return -1;
      }

      fprintf(name_file_fp, "%s", as->as_appliance_name);
      fclose(name_file_fp);

      return 0;
    } else {
      perror("appstate_open_name: fopen");
      return -1;
    }
  }

  err = fread(as->as_appliance_name, 1, sizeof(as->as_appliance_name) - 1, name_file_fp);
  if ( err <= 0 ) {
    fclose(name_file_fp);
    fprintf(stderr, "No name present in name file\n");
    return -1;
  } else {
    as->as_appliance_name[err] = '\0';
  }

  fclose(name_file_fp);

  return 0;
}

static int appstate_open_local(struct appstate *as, struct appconf *ac) {
  struct sockaddr_un addr;
  int sk, err;

  sk = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if ( sk < 0 ) {
    perror("appstate_open_local: socket");
    return -1;
  }

  err = set_socket_nonblocking(sk);
  if ( err < 0 ) {
    perror("appstate_open_local: set_socket_nonblocking");
    goto error;
  }

  addr.sun_family = AF_UNIX;
  err = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/" APPLIANCED_LOCAL_API_SOCK, ac->ac_conf_dir);
  if ( err >= sizeof(addr.sun_path) ) {
    fprintf(stderr, "appstate_open_local: overflowed sockaddr_un sun_path\n");
    goto error;
  }

  err = bind(sk, (struct sockaddr *)&addr, sizeof(addr));
  if ( err < 0 ) {
    if ( errno == EADDRINUSE ) {
      err = unlink(addr.sun_path);
      if ( err < 0 ) {
        perror("appstate_open_local: unlink");
        goto error;
      }

      err = bind(sk, (struct sockaddr *) &addr, sizeof(addr));
      if ( err < 0 ) {
        perror("appstate_open_local: bind (after unlink");
        goto error;
      }
    } else {
      perror("appstate_open_local: bind");
      goto error;
    }
  }

  err = listen(sk, 5);
  if ( err < 0 ) {
    perror("appstate_open_local: listen");
    goto error;
  }

  as->as_local_fd = sk;

  return 0;

 error:
  close(sk);
  return -1;
}

static int generate_cookie_cb(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
  SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
  struct appstate *as;

  if ( !ctx ) return 0;

  as = SSL_CTX_get_appstate(ctx);
  if ( !as ) return 0;

  *cookie_len = DTLS1_COOKIE_LENGTH;
  if ( pthread_mutex_lock(&as->as_dtls_cookies_mutex) == 0 ) {
    int ret = 1;
    if ( dtlscookies_generate_cookie(&as->as_dtls_cookies, cookie, cookie_len) < 0 ) {
      fprintf(stderr, "dtlscookies_generate failed\n");
      ret = 0;
    }
    pthread_mutex_unlock(&as->as_dtls_cookies_mutex);

    return ret;
  } else return 0;
}

static int verify_cookie_cb(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
  SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
  struct appstate *as;

  if ( !ctx ) return 0;

  as = SSL_CTX_get_appstate(ctx);
  if ( !as ) return 0;

  if ( pthread_mutex_lock(&as->as_dtls_cookies_mutex) == 0 ) {
    int ret;
    ret = dtlscookies_verify_cookie(&as->as_dtls_cookies, cookie, cookie_len);
    if ( ret < 0 ) {
      fprintf(stderr, "dtlscookies_verify_cookie fails\n");
      ret = 0;
    }
    pthread_mutex_unlock(&as->as_dtls_cookies_mutex);
    return ret;
  } else
    return 0;
}

static int appstate_create_dtls_ctx(struct appstate *as) {
  int err;

  as->as_dtls_ctx = SSL_CTX_new(DTLS_method());
  if ( !as->as_dtls_ctx ) {
    fprintf(stderr, "appstate_create_dtls_ctx: could not create context\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  err = SSL_CTX_set_cipher_list(as->as_dtls_ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
  if ( err != 1 ) {
    fprintf(stderr, "appstate_create_dtls_ctx: Could not add SSL ciphers\n");
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(as->as_dtls_ctx);
    return -1;
  }

  err = SSL_CTX_use_certificate(as->as_dtls_ctx, as->as_cert);
  if ( err != 1 ) {
    fprintf(stderr, "appstate_create_dtls_ctx: Could not set SSL certificate\n");
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(as->as_dtls_ctx);
    return -1;
  }

  err = SSL_CTX_use_PrivateKey(as->as_dtls_ctx, as->as_privkey);
  if ( err != 1 ) {
    fprintf(stderr, "appstate_create_dtls_ctx: Could not set SSL private key\n");
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(as->as_dtls_ctx);
    return -1;
  }

  err = SSL_CTX_check_private_key(as->as_dtls_ctx);
  if ( err != 1 ) {
    fprintf(stderr, "appstate_create_dtls_ctx: Invalid private key for SSL context\n");
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(as->as_dtls_ctx);
    return -1;
  }

  if ( !SSL_CTX_set_appstate(as->as_dtls_ctx, as) ) {
    fprintf(stderr, "appstate_create_dtls_ctx: Could not set context appstate\n");
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(as->as_dtls_ctx);
    return -1;
  }

  if ( SSL_CTX_set_alpn_protos(as->as_dtls_ctx, intrustd_alpn_protos, sizeof(intrustd_alpn_protos)) != 0 ) {
    fprintf(stderr, "appstate_create_dtls_ctx: could not set ALPN protos\n");
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(as->as_dtls_ctx);
    return -1;
  }

  // For firefox
  if ( SSL_CTX_set_tlsext_use_srtp(as->as_dtls_ctx, "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32:SRTP_AEAD_AES_128_GCM:SRTP_AEAD_AES_256_GCM") != 0 ) {
    fprintf(stderr, "appstate_create_dtls_ctx: Could not set use-srtp\n");
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(as->as_dtls_ctx);
    return -1;
  }

  SSL_CTX_set_alpn_select_cb(as->as_dtls_ctx, appstate_alpn_select_callback, NULL);
  SSL_CTX_set_verify(as->as_dtls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     appstate_verify_callback);
  SSL_CTX_set_cookie_generate_cb(as->as_dtls_ctx, generate_cookie_cb);
  SSL_CTX_set_cookie_verify_cb(as->as_dtls_ctx, verify_cookie_cb);

  return 0;
}

static int appstate_bump_persona_avatar(struct appstate *as, struct persona *p) {
  char persona_avatar_path[PATH_MAX], persona_hex_str[PERSONA_ID_X_LENGTH + 1];
  int err;
  FILE *avatar_fp;

  err = snprintf(persona_avatar_path, PATH_MAX, "%s/personas/%s/avatar.png", as->as_conf_dir,
                 hex_digest_str((unsigned char *) p->p_persona_id, persona_hex_str, PERSONA_ID_LENGTH));
  if ( err >= sizeof(persona_avatar_path) ) {
    fprintf(stderr, "appstate_bump_persona_avatar: buffer overflow while writing avatar path\n");
    return -1;
  }

  avatar_fp = fopen(persona_avatar_path, "rb");
  if ( avatar_fp ) {
    persona_set_photo_data_fp(p, "image/png", avatar_fp);
    fclose(avatar_fp);
  } else
    persona_unset_photo(p);

  return 0;
}

// as -- struct appstate, ac -- struct appconf
// persona_id -- Must be of length PERSONA_ID_LENGTH
// persona_dir -- path to persona directory
static int appstate_open_persona(struct appstate *as, struct appconf *ac,
                                 unsigned char *persona_id, char *persona_dir) {
  int err;
  char persona_info_path[PATH_MAX];
  struct persona *p;
  FILE *persona_fp;

  err = snprintf(persona_info_path, PATH_MAX, "%s/persona", persona_dir);
  if ( err >= sizeof(persona_info_path) ) {
    fprintf(stderr, "appstate_open_persona: buffer overflow while writing path\n");
    return -1;
  }

  persona_fp = fopen(persona_info_path, "rt");
  if ( !persona_fp ) {
    perror("appstate_open_persona: could not open persona file");
    return -1;
  }

  p = malloc(sizeof(struct persona));
  if ( !p ) {
    fclose(persona_fp);
    fprintf(stderr, "appstate_open_persona: could not allocate new persona");
    return -1;
  }

  memcpy(p->p_persona_id, persona_id, sizeof(p->p_persona_id));

  err = persona_init_fp(p, as, persona_fp);
  if ( err < 0 ) {
    free(p);
    fclose(persona_fp);
    return -1;
  }

  fclose(persona_fp);

  // Now read the private key
  err = snprintf(persona_info_path, PATH_MAX, "%s/key", persona_dir);
  if ( err >= sizeof(persona_info_path) ) {
    fprintf(stderr, "appstate_open_persona: buffer overflow while writing key path\n");
    PERSONA_UNREF(p);
    return -1;
  }

  persona_fp = fopen(persona_info_path, "rt");
  if ( !persona_fp ) {
    perror("appstate_open_persona: could not open key");
    PERSONA_UNREF(p);
    return -1;
  }

  p->p_private_key = PEM_read_PrivateKey(persona_fp, NULL, NULL, NULL);
  if ( !p->p_private_key ) {
    fprintf(stderr, "appstate_open_persona: could not open private key\n");
    ERR_print_errors_fp(stderr);
    PERSONA_UNREF(p);
    fclose(persona_fp);
    return -1;
  }

  fclose(persona_fp);

  if ( appstate_bump_persona_avatar(as, p) < 0 ) {
    PERSONA_UNREF(p);
    return -1;
  }

  if ( pthread_rwlock_wrlock(&as->as_personas_mutex) == 0 ) {
    struct persona *existing;
    HASH_FIND(p_hh, as->as_personas, p->p_persona_id, PERSONA_ID_LENGTH, existing);
    pthread_rwlock_unlock(&as->as_personas_mutex);
    if ( existing ) {
      fprintf(stderr, "appstate_open_persona: persona with this id already exists\n");
      PERSONA_UNREF(p);
      return -1;
    } else {
      HASH_ADD(p_hh, as->as_personas, p_persona_id, PERSONA_ID_LENGTH, p);
    }
    return 0;
  } else {
    fprintf(stderr, "appstate_open_persona: could not lock app state mutex\n");
    PERSONA_UNREF(p);
    return -1;
  }
}

static int appstate_open_personas(struct appstate *as, struct appconf *ac) {
  DIR *personas_d;
  struct dirent *ent;
  struct stat ent_stat;
  char personas_dir[PATH_MAX];
  unsigned char persona_id[PERSONA_ID_LENGTH];
  int err;

  err = snprintf(personas_dir, sizeof(personas_dir), "%s/personas/", ac->ac_conf_dir);
  if ( err >= sizeof(personas_dir) ) {
    fprintf(stderr, "appstate_open_personas: buffer overflow while writing path\n");
    return -1;
  }

  personas_d = opendir(personas_dir);
  if ( !personas_d ) {
    if ( errno == ENOENT ) {
      return 0;
    } else {
      perror("appstate_open_personas: could not read personas directory");
      return -1;
    }
  }

  for ( errno = 0, ent = readdir(personas_d); ent; errno = 0, ent = readdir(personas_d) ) {
    if ( strlen(ent->d_name) != PERSONA_ID_X_LENGTH ) continue;

    err = parse_hex_str(ent->d_name, (unsigned char *)persona_id, PERSONA_ID_LENGTH);
    if ( err < 0 ) {
      fprintf(stderr, "appstate_open_personas: could not parse hex path %s\n", ent->d_name);
      closedir(personas_d);
      return -1;
    }

    err = snprintf(personas_dir, sizeof(personas_dir),
                   "%s/personas/%s", ac->ac_conf_dir, ent->d_name);
    if ( err >= sizeof(personas_dir) ) {
      fprintf(stderr, "appstate_open_personas: buffer overflow while writing path\n");
      closedir(personas_d);
      return -1;
    }

    err = stat(personas_dir, &ent_stat);
    if ( err < 0 ) {
      perror("appstate_open_personas: could not stat persona dir entry");
      closedir(personas_d);
      return -1;
    }

    // if this entry is not a directory continue
    if ( !S_ISDIR(ent_stat.st_mode) ) continue;

    err = appstate_open_persona(as, ac, persona_id, personas_dir);
    if ( err < 0 ) {
      fprintf(stderr, "Error loading persona %s\n", ent->d_name);
    } else {
      fprintf(stderr, "Successfully loaded persona %s\n", ent->d_name);
    }
  }

  if ( errno != 0 ) {
    fprintf(stderr, "appstate_open_personas: could not list personas %s\n", strerror(err));
    closedir(personas_d);
    return -1;
  }

  closedir(personas_d);
  return 0;
}

static int appstate_open_trusted_keys(struct appstate *as, struct appconf *ac) {
  char trusted_keys_dir[PATH_MAX];
  DIR *keys_d;
  struct dirent *ent;
  struct stat ent_stat;
  int err;

  err = snprintf(trusted_keys_dir, sizeof(trusted_keys_dir),
                "%s/trusted_keys", ac->ac_conf_dir);
  if ( err >= sizeof(trusted_keys_dir) ) {
    fprintf(stderr, "appstate_open_trusted_keys: buffer overflow while writing path\n");
    return -1;
  }

  keys_d = opendir(trusted_keys_dir);
  if ( !keys_d ) {
    fprintf(stderr, "appstate_open_trusted_keys: no trusted keys found\n");
    return 0;
  }

  for ( errno = 0, ent = readdir(keys_d); ent; errno = 0, ent = readdir(keys_d) ) {
    FILE *pubkey;
    EVP_PKEY *key;

    err = snprintf(trusted_keys_dir, sizeof(trusted_keys_dir),
                   "%s/trusted_keys/%s", ac->ac_conf_dir, ent->d_name);
    if ( err < 0 ) {
      fprintf(stderr, "appstate_open_trusted_keys: buffer overflow while writing path. Skipping %s\n", ent->d_name);
      continue;
    }

    err = stat(trusted_keys_dir, &ent_stat);
    if ( err < 0 ) {
      fprintf(stderr, "appstate_open_trusted_keys: could not stat %s\n", trusted_keys_dir);
      continue;
    }

    if ( !S_ISREG(ent_stat.st_mode) ) continue;

    pubkey = fopen(trusted_keys_dir, "rt");
    if ( !pubkey ) {
      perror("appstate_open_trusted_keys: fopen");
      fprintf(stderr, "While opening %s\n", trusted_keys_dir);
      continue;
    }

    key = PEM_read_PUBKEY(pubkey, NULL, NULL, NULL);
    if ( !key ) {
      fprintf(stderr, "appstate_open_trusted_keys: could not read key file\n");
      ERR_print_errors_fp(stderr);
      fclose(pubkey);
      continue;
    }

    fclose(pubkey);

    as->as_trusted_key_count++;
    as->as_trusted_keys = realloc(as->as_trusted_keys,
                                  sizeof(*as->as_trusted_keys) * as->as_trusted_key_count);
    if ( !as->as_trusted_keys ) {
      fprintf(stderr, "appstate_open_trusted_keys: could not reallocate keys\n");
      abort();
    }

    as->as_trusted_keys[as->as_trusted_key_count - 1] = key;
  }

  fprintf(stderr, "appstate_open_trusted_keys: read %d trusted keys\n", as->as_trusted_key_count);

  return 0;
}

static int appstate_open_flocks(struct appstate *as, struct appconf *ac) {
  char flocks_path[PATH_MAX];
  char flocks_line[1024];
  char flock_uri_str[sizeof(flocks_line)];
  char cert_digest[FLOCK_SIGNATURE_DIGEST_SZ * 2 + 1];
  FILE *flocks;
  int err;

  UriParserStateA uri_parser;
  UriUriA flock_uri_uri;
  uri_parser.uri = &flock_uri_uri;

  err = snprintf(flocks_path, sizeof(flocks_path), FLOCKS_PATH_TEMPLATE, as->as_conf_dir);
  if ( err >= sizeof(flocks_path) ) {
    fprintf(stderr, "appstate_open_flocks: buffer overflow while writing path\n");
    return -1;
  }

  flocks = fopen(flocks_path, "rt");
  if ( !flocks ) {
    fprintf(stderr, "appstate_open_flocks: Could not read flocks file\n");
    if ( errno == ENOENT  )
      return 0;
    else
      return -1;
  }

  // Read each line
  while ( fgets(flocks_line, sizeof(flocks_line), flocks) ) {
    int line_length = strlen(flocks_line);
    if ( line_length == 0 ) continue;

    if ( flocks_line[line_length - 1] == '\n' || feof(flocks) ) {
      struct flock *new_flock;

      err = sscanf(flocks_line, "%s %" FLOCK_SIGNATURE_DIGEST_HEX_SZ "s", flock_uri_str, cert_digest);
      if ( err != 2 ) {
        fclose(flocks);
        fprintf(stderr, "appstate_open_flocks: invalid line\n");
        return -1;
      }

      // Attempt to parse URI
      if ( uriParseUriA(&uri_parser, flock_uri_str) != URI_SUCCESS ) {
        fclose(flocks);
        fprintf(stderr, "appstate_open_flocks: invalid url %s\n", flock_uri_str);
        return -1;
      }

      new_flock = malloc(sizeof(struct flock));
      if ( !new_flock ) {
        fclose(flocks);
        fprintf(stderr, "appstate_open_flocks: out of memory\n");
        return -1;
      }
      flock_clear(new_flock);

      if ( parse_hex_str(cert_digest, new_flock->f_expected_digest,
                         sizeof(new_flock->f_expected_digest)) !=
           sizeof(new_flock->f_expected_digest) ) {
        fclose(flocks);
        free(new_flock);
        fprintf(stderr, "Invalid certificate digest %s\n", cert_digest);
        return -1;
      }

      new_flock->f_flags |= FLOCK_FLAG_VALIDATE_CERT;

      if ( flock_assign_uri(new_flock, &flock_uri_uri) < 0 ) {
        fclose(flocks);
        free(new_flock);
        fprintf(stderr, "appstate_open_flocks: could not create flock with uri %s\n", flock_uri_str);
        return -1;
      }

      if ( appstate_create_flock(as, new_flock, 1) < 0 ) {
        flock_release(new_flock);
        fclose(flocks);
        fprintf(stderr, "appstate_open_flocks: could not add flock to appliance\n");
      }

      // Valid line
    } else {
      fclose(flocks);
      fprintf(stderr, "appstate_open_flocks: line too long\n");
      return -1;
    }
  }

  fclose(flocks);

  return 0;
}

static int appstate_open_apps(struct appstate *as, struct appconf *ac) {
  FILE *apps;
  int err;
  char apps_path[PATH_MAX], apps_line[1024];

  err = snprintf(apps_path, sizeof(apps_path), APPS_PATH_TEMPLATE, as->as_conf_dir);
  if ( err >= sizeof(apps_path) ) {
    fprintf(stderr, "appstate_open_apps: buffer overflow while writing path\n");
    return -1;
  }

  apps = fopen(apps_path, "rt");
  if ( !apps ) {
    perror("appstate_open_apps: could not read apps file");
    if ( errno == ENOENT )
      return 0;
    else
      return -1;
  }

  while ( fgets(apps_line, sizeof(apps_line), apps) ) {
    int line_length = strlen(apps_line);
    if ( line_length == 0 ) continue;

    if ( apps_line[line_length - 1] == '\n' || feof(apps) ) {
      struct appmanifest *mf;
      struct app *a;
      char apps_url[1024], mf_digest_str[SHA256_DIGEST_LENGTH * 2 + 1];
      unsigned char mf_digest[SHA256_DIGEST_LENGTH];
      err = sscanf(apps_line, "%s %64s", apps_url, mf_digest_str);
      if ( err != 2 ) {
        fclose(apps);
        fprintf(stderr, "appstate_open_apps: invalid line\n");
        return -1;
      }

      if ( parse_hex_str(mf_digest_str, mf_digest, sizeof(mf_digest)) < 0 ) {
        fclose(apps);
        fprintf(stderr, "appstate_open_apps: invalid manifest digest %s\n", mf_digest_str);
        return -1;
      }

      err = snprintf(apps_path, sizeof(apps_path), "%s/manifests/%s", as->as_conf_dir, mf_digest_str);
      if ( err >= sizeof(apps_path) ) {
        fclose(apps);
        fprintf(stderr, "appstate_open_apps: path overflow while reading manifest\n");
        return -1;
      }

      mf = appmanifest_parse_from_file(apps_path, mf_digest, as->as_system);
      if ( !mf ) {
        fprintf(stderr, "appstate_open_apps: could not read app manifest for %s\n", mf_digest_str);

        // Do not error on this, but read whatever applications we can
        continue;
      }

      a = application_from_manifest(mf);
      if ( !a ) {
        fclose(apps);
        fprintf(stderr, "appstate_open_apps: could not create app from manifest %s\n", mf_digest_str);
        return -1;
      }

      appstate_update_application_state(as, a);

      HASH_ADD_KEYPTR(app_hh, as->as_apps, a->app_domain, strlen(a->app_domain), a);
    } else {
      fclose(apps);
      fprintf(stderr, "appstate_open_apps: could not add app to appliance: line overflow\n");
      return -1;
    }
  }

  fclose(apps);
  return 0;
}

void appstate_clear(struct appstate *as) {
  as->as_appliance_name[0] = '\0';
  as->as_conf_dir = NULL;
  as->as_webrtc_proxy_path = NULL;
  as->as_persona_init_path = NULL;
  as->as_app_instance_init_path = NULL;
  as->as_system = NULL;
  as->as_resolv_conf = NULL;
  as->as_mutexes_initialized = 0;
  as->as_cert = NULL;
  as->as_privkey = NULL;
  as->as_dtls_ctx = NULL;
  as->as_trusted_key_count = 0;
  as->as_trusted_keys = NULL;
  as->as_flocks = NULL;
  as->as_personas = NULL;
  as->as_cur_personaset = NULL;
  as->as_tokens = NULL;
  as->as_apps = NULL;
  as->as_updates = NULL;
  as->as_local_fd = 0;
  fdsub_clear(&as->as_local_sub);
  bridge_clear(&as->as_bridge);
  eventloop_clear(&as->as_eventloop);
  dtlscookies_clear(&as->as_dtls_cookies);
}

int appstate_setup(struct appstate *as, struct appconf *ac) {
  char path[PATH_MAX];
  uid_t our_uid = geteuid();
  int err;

  appstate_clear(as);

  if ( !(AC_VALGRIND(ac)) ) {
    // this will fork, and return only in the child.
    //
    // The parent becomes the bridge controller.
    err = bridge_init(&as->as_bridge, as, our_uid,
                      ac->ac_app_user, ac->ac_app_user_group,
                      ac->ac_daemon_user, ac->ac_daemon_group,
                      ac->ac_iproute_bin, ac->ac_ebroute_bin);
    if ( err < 0 ) {
      fprintf(stderr, "appstate_setup: bridge_init failed\n");
      goto error;
    }
  }

  // Drop privileges
  if ( our_uid == 0 ) {
    fprintf(stderr, "Dropping privileges to %d:%d\n", ac->ac_daemon_user, ac->ac_daemon_group);

    if ( setgid(ac->ac_daemon_group) < 0 ) {
      perror("setresgid");
      goto error;
    }

    if ( setuid(ac->ac_daemon_user) < 0 ) {
      perror("setreuid");
      goto error;
    }
  }
  as->as_conf_dir = ac->ac_conf_dir;
  as->as_webrtc_proxy_path = ac->ac_webrtc_proxy_path;
  as->as_persona_init_path = ac->ac_persona_init_path;
  as->as_app_instance_init_path = ac->ac_app_instance_init_path;
  as->as_system = ac->ac_system_config;
  as->as_resolv_conf = ac->ac_resolv_conf;

  err = mkdir_recursive(ac->ac_conf_dir);
  if ( err < 0 ) {
    perror("appconf_setup: mkdir_recursive");
    return -1;
  }

  err = snprintf(path, sizeof(path), "%s/nix-cache", ac->ac_conf_dir);
  if ( err >= sizeof(path) ) {
    fprintf(stderr, "appconf_setup: path overflow\n");
    return -1;
  }
  err = mkdir_recursive(path);
  if ( err < 0 ) {
    perror("appconf_setup: mkdir_recursive");
    return -1;
  }

  err = snprintf(path, sizeof(path), "%s/nix-roots", ac->ac_conf_dir);
  if ( err >= sizeof(path) ) {
    fprintf(stderr, "appconf_setup: path overflow\n");
    return -1;
  }
  err = mkdir_recursive(path);
  if ( err < 0 ) {
    perror("appconf_setup: mkdir_recursive");
    return -1;
  }

  // Open key file. Generate one if necessary
  if ( appstate_open_keys(as, ac) < 0 )
    goto error;

  if ( appstate_open_name(as, ac) < 0 )
    goto error;

  fprintf(stderr, "Our appliance is named %s\n", as->as_appliance_name);

  // Open local unix socket
  if ( appstate_open_local(as, ac) < 0 )
    goto error;

  if ( appstate_create_dtls_ctx(as) < 0 )
    goto error;

  err = eventloop_init(&as->as_eventloop);
  if ( err != 0 ) {
    fprintf(stderr, "eventloop_init: %s\n", strerror(errno));
    goto error;
  }

  err = pthread_rwlock_init(&as->as_flocks_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "appstate_setup: could not initialize flocks mutex: %s\n", strerror(err));
    goto error;
  }
  as->as_mutexes_initialized |= AS_FLOCK_MUTEX_INITIALIZED;

  err = pthread_rwlock_init(&as->as_personas_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "appstate_setup: could not initialize personas mutex: %s\n", strerror(err));
    goto error;
  }
  as->as_mutexes_initialized |= AS_PERSONAS_MUTEX_INITIALIZED;

  err = pthread_rwlock_init(&as->as_applications_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "appstate_setup: could not initialized applications mutex: %s\n", strerror(err));
    goto error;
  }
  as->as_mutexes_initialized |= AS_APPS_MUTEX_INITIALIZED;

  err = pthread_mutex_init(&as->as_dtls_cookies_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "appstate_setup: could not initialize dtls cookies mutex: %s\n", strerror(err));
    goto error;
  }
  as->as_mutexes_initialized |= AS_DTLS_COOKIES_MUTEX_INITIALIZED;

  err = pthread_mutex_init(&as->as_tokens_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "appstate_setup: could not initialize tokens mutex: %s\n", strerror(err));
    goto error;
  }
  as->as_mutexes_initialized |= AS_TOKENS_MUTEX_INITIALIZED;

  if ( dtlscookies_init(&as->as_dtls_cookies,
                        30, 60 * 5, 32) < 0 ) {
    fprintf(stderr, "appstate_setup: could not initialize dtls cookies\n");
    goto error;
  }

  if ( appstate_open_trusted_keys(as, ac) < 0 )
    goto error;

  if ( appstate_open_flocks(as, ac) < 0 )
    goto error;

  if ( appstate_open_apps(as, ac) < 0 )
    goto error;

  if ( appstate_open_personas(as, ac) < 0 )
    goto error;

  return 0;

 error:
  appstate_release(as);
  return -1;
}

void appstate_release(struct appstate *as) {
  struct token *cur_token, *tmp_token;

  if ( as->as_cert ) {
    X509_free(as->as_cert);
    as->as_cert = NULL;
  }

  if ( as->as_privkey ) {
    EVP_PKEY_free(as->as_privkey);
    as->as_privkey = NULL;
  }

  if ( as->as_dtls_ctx ) {
    SSL_CTX_free(as->as_dtls_ctx);
    as->as_dtls_ctx = NULL;
  }

  bridge_release(&as->as_bridge);

  if ( as->as_local_fd ) {
    close(as->as_local_fd);
    as->as_local_fd = 0;
  }

  if ( as->as_mutexes_initialized & AS_FLOCK_MUTEX_INITIALIZED ) {
    pthread_rwlock_destroy(&as->as_flocks_mutex);
  }
  as->as_mutexes_initialized &= ~AS_FLOCK_MUTEX_INITIALIZED;

  if ( as->as_mutexes_initialized & AS_PERSONAS_MUTEX_INITIALIZED ) {
    pthread_rwlock_destroy(&as->as_personas_mutex);
  }
  as->as_mutexes_initialized &= ~AS_PERSONAS_MUTEX_INITIALIZED;

  if ( as->as_mutexes_initialized & AS_APPS_MUTEX_INITIALIZED ) {
    pthread_rwlock_destroy(&as->as_applications_mutex);
  }
  as->as_mutexes_initialized &= ~AS_APPS_MUTEX_INITIALIZED;

  if ( as->as_mutexes_initialized & AS_DTLS_COOKIES_MUTEX_INITIALIZED )
    pthread_mutex_destroy(&as->as_dtls_cookies_mutex);
  as->as_mutexes_initialized &= ~AS_DTLS_COOKIES_MUTEX_INITIALIZED;

  HASH_ITER(tok_hh, as->as_tokens, cur_token, tmp_token) {
    TOKEN_UNREF(cur_token);
  }
  HASH_CLEAR(tok_hh, as->as_tokens);
  if ( as->as_mutexes_initialized & AS_TOKENS_MUTEX_INITIALIZED )
    pthread_mutex_destroy(&as->as_tokens_mutex);
  as->as_mutexes_initialized &= ~AS_TOKENS_MUTEX_INITIALIZED;

  // TODO release flocks, personas, and applications

  if ( as->as_cur_personaset ) {
    PERSONASET_UNREF(as->as_cur_personaset);
    as->as_cur_personaset = NULL;
  }
}

static void appstatefn(struct eventloop *el, int op, void *arg) {
  struct appstate *as = APPSTATE_FROM_EVENTLOOP(el);
  struct appupdater *au;
  //  struct fdevent *fde;
  struct qdevent *qde;
  struct flock *flk;
  int new_sk;

  char flock_line[1024];
  unsigned char pk_digest[FLOCK_SIGNATURE_DIGEST_SZ];

  struct app *app, *tmp_app;

  switch ( op ) {
  case OP_APPSTATE_AUTOSTART_APPS:
    // Automatically launch auto start, singleton apps
    SAFE_RWLOCK_RDLOCK(&as->as_applications_mutex);
    HASH_ITER(app_hh, as->as_apps, app, tmp_app) {
      int autostart = 0;
      // Start this application
      if ( pthread_mutex_lock(&app->app_mutex) == 0 ) {
        autostart = app->app_flags & APP_FLAG_AUTOSTART;
        if ( autostart )
          fprintf(stderr, "Starting %s\n", app->app_domain);
        pthread_mutex_unlock(&app->app_mutex);
      }

      if ( autostart ) {
        launch_app_instance(as, NULL, app);
      }
    }
    pthread_rwlock_unlock(&as->as_applications_mutex);
    break;

  case OP_APPSTATE_ACCEPT_LOCAL:
    fprintf(stderr, "Attempting to accept connection\n");
    //    fde = (struct fdevent *)arg;

    new_sk = accept(as->as_local_fd, NULL, NULL);
    if ( new_sk < 0 ) {
      perror("appstatefn: accept");
      return;
    }

    // Start a new local connection
    if ( localapi_alloc(as, new_sk) < 0 ) {
      close(new_sk);
      fprintf(stderr, "Could not allocate local connection\n");
    }

    eventloop_subscribe_fd(el, as->as_local_fd, FD_SUB_ACCEPT, &as->as_local_sub);

    return;

  case OP_APPSTATE_SAVE_FLOCK:
    qde = (struct qdevent *)arg;
    flk = STRUCT_FROM_BASE(struct flock, f_on_should_save, qde->qde_sub);

    SAFE_MUTEX_LOCK(&flk->f_mutex);
    fprintf(stderr, "Request to save flock %s\n", flk->f_uri_str);

    if ( appstate_format_flock_line(flk, flock_line, sizeof(flock_line), pk_digest) == 0 ) {
      memcpy(flk->f_expected_digest, pk_digest, sizeof(flk->f_expected_digest));
      flk->f_flags |= FLOCK_FLAG_VALIDATE_CERT;
      pthread_mutex_unlock(&flk->f_mutex);

      SAFE_RWLOCK_WRLOCK(&as->as_flocks_mutex);
      appstate_add_flock(as, flock_line);
      pthread_rwlock_unlock(&as->as_flocks_mutex);
    } else {
      pthread_mutex_unlock(&flk->f_mutex);
      fprintf(stderr, "appstatefn: overflow while trying to save flock\n");
    }

    return;

  case OP_APPSTATE_APPLICATION_UPDATED:
    au = APPUPDATER_FROM_COMPLETION_EVENT(arg);
    do {
      struct appupdater *existing;
      SAFE_RWLOCK_WRLOCK(&as->as_applications_mutex);
      HASH_FIND(au_hh, as->as_updates, au->au_url, strlen(au->au_url), existing);
      if ( existing == au ) {
        HASH_DELETE(au_hh, as->as_updates, existing);
        APPUPDATER_UNREF(au);
      } else abort();
      pthread_rwlock_unlock(&as->as_applications_mutex);
    } while (0);
    return;

  default:
    fprintf(stderr, "appstatefn: Unknown op %d\n", op);
    break;
  }
}

void appstate_start_services(struct appstate *as, struct appconf *ac) {
  if ( !AC_VALGRIND(ac) )
    bridge_start(&as->as_bridge, &as->as_eventloop);

  fdsub_init(&as->as_local_sub, &as->as_eventloop, as->as_local_fd, OP_APPSTATE_ACCEPT_LOCAL, appstatefn);
  eventloop_subscribe_fd(&as->as_eventloop, as->as_local_fd, FD_SUB_ACCEPT, &as->as_local_sub);

  qdevtsub_init(&as->as_autostart_evt, OP_APPSTATE_AUTOSTART_APPS, appstatefn);
  if ( !AC_VALGRIND(ac) ) {
    eventloop_queue(&as->as_eventloop, &as->as_autostart_evt);
  }
}

int appstate_create_flock(struct appstate *as, struct flock *f, int is_old) {
  struct flock *f_exist, *f_new = NULL;
  int ret = 0;

  if ( pthread_rwlock_wrlock(&as->as_flocks_mutex) != 0 ) {
    errno = EBUSY;
    return -1;
  }

  HASH_FIND(f_hh, as->as_flocks, f->f_uri_str, strlen(f->f_uri_str), f_exist);
  if ( f_exist ) {
    errno = EEXIST;
    ret = -1;
  } else {
    f_new = (struct flock *) malloc(sizeof(struct flock));
    if ( !f_new ) {
      errno = ENOMEM;
      ret = -1;
    } else {
      flock_move(f_new, f);

      if ( !is_old )
        f_new->f_flags |= FLOCK_FLAG_PENDING;
      qdevtsub_init(&f_new->f_on_should_save, OP_APPSTATE_SAVE_FLOCK, appstatefn);

      HASH_ADD_KEYPTR(f_hh, as->as_flocks, f_new->f_uri_str, strlen(f_new->f_uri_str), f_new);
    }
  }

  pthread_rwlock_unlock(&as->as_flocks_mutex);

  // The flock will be saved once we have connected to it and verified its certificates
  if ( f_new )
    flock_start_service(f_new, &as->as_eventloop);

  return ret;
}

int appstate_save_persona(struct appstate *as, struct persona *p) {
  char persona_dir[PATH_MAX], persona_hex_str[PERSONA_ID_X_LENGTH + 1];
  int err, ret = 0, fp;
  FILE *persona_fp;
  struct stat key_stat;

  if ( pthread_mutex_lock(&p->p_mutex) != 0 ) return -1;

  err = snprintf(persona_dir, sizeof(persona_dir),
                 "%s/personas/%s", as->as_conf_dir,
                 hex_digest_str((unsigned char *) p->p_persona_id, persona_hex_str, PERSONA_ID_LENGTH));
  if ( err >= sizeof(persona_dir) ) {
    fprintf(stderr, "appstate_save_persona: not enough space for persona dir path\n");
    ret = -1;
    goto done;
  }

  if ( mkdir_recursive(persona_dir) < 0 ) {
    fprintf(stderr, "appstate_save_persona: could not create directory\n");
    ret = -1;
    goto done;
  }

  err = snprintf(persona_dir, sizeof(persona_dir),
                 "%s/personas/%s/persona", as->as_conf_dir,
                 hex_digest_str((unsigned char *) p->p_persona_id, persona_hex_str, PERSONA_ID_LENGTH));
  if ( err >= sizeof(persona_dir) ) {
    fprintf(stderr, "appstate_save_persona: not enough space for persona profile path\n");
    ret = -1;
    goto done;
  }

  persona_fp = fopen(persona_dir, "wt");
  if ( !persona_fp ) {
    perror("appstate_save_persona: fopen");
    ret = -1;
    goto done;
  }

  if ( persona_save_fp(p, persona_fp) < 0 ) {
    ret = -1;
    fclose(persona_fp);
    goto done;
  }

  fclose(persona_fp);

  // Make sure the key file is saved as well
  err = snprintf(persona_dir, sizeof(persona_dir),
                 "%s/personas/%s/key", as->as_conf_dir,
                 hex_digest_str((unsigned char *) p->p_persona_id, persona_hex_str, PERSONA_ID_LENGTH));
  if ( err >= sizeof(persona_dir) ) {
    fprintf(stderr, "appstate_save_persona: not enough space for key file path\n");
    ret = -1;
    goto done;
  }

  // Check to see if the file exists
  err = stat(persona_dir, &key_stat);
  if ( err == 0 ) goto done;
  else if ( errno != ENOENT ) {
    perror("appstate_save_persona: stat");
    ret = -1;
    goto done;
  }

  fp = open(persona_dir, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR | S_IWUSR);
  if ( fp < 0 ) {
    perror("appstate_save_persona: open(key)");
    ret = -1;
    goto done;
  }

  persona_fp = fdopen(fp, "wt");
  if ( !persona_fp ) {
    perror("appstate_save_persona: fopen(key)");
    close(fp);
    ret = -1;
    goto done;
  }

  if ( !PEM_write_PrivateKey(persona_fp, p->p_private_key, NULL, NULL, 0, NULL, NULL) ) {
    fprintf(stderr, "appstate_save_persona: could not write private key\n");
    ERR_print_errors_fp(stderr);
    fclose(persona_fp);
    ret = -1;
    goto done;
  }
  fclose(persona_fp);

 done:
  pthread_mutex_unlock(&p->p_mutex);
  return ret;
}

int appstate_create_persona(struct appstate *as,
                            struct personacreateinfo *pci,
                            struct persona **ret_ptr) {
  struct persona *p, *already_existing;
  EC_KEY *curve;
  EVP_PKEY *key;

  curve = EC_KEY_new_by_curve_name(DEFAULT_EC_CURVE_NAME);
  if ( !curve ) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if ( !EC_KEY_generate_key(curve) ) {
    ERR_print_errors_fp(stderr);
    EC_KEY_free(curve);
    return -1;
  }
  EC_KEY_set_asn1_flag(curve, OPENSSL_EC_NAMED_CURVE); // Make sure we save this with a name

  key = EVP_PKEY_new();
  if ( !key) {
    ERR_print_errors_fp(stderr);
    EC_KEY_free(curve);
    return -1;
  }

  if ( !EVP_PKEY_assign_EC_KEY(key, curve) ) {
    ERR_print_errors_fp(stderr);
    EC_KEY_free(curve);
    EVP_PKEY_free(key);
    return -1;
  }

  p = malloc(sizeof(struct persona));
  if ( !p ) {
    EVP_PKEY_free(key);
    return -1;
  }

  pthread_rwlock_wrlock(&as->as_personas_mutex);
  do {
    if ( !RAND_bytes((unsigned char *) p->p_persona_id, PERSONA_ID_LENGTH) ) {
      PERSONA_UNREF(p);
      pthread_rwlock_unlock(&as->as_personas_mutex);
      return -1;
    }

    HASH_FIND(p_hh, as->as_personas, p->p_persona_id, PERSONA_ID_LENGTH, already_existing);
  } while ( already_existing );

  if ( persona_init(p, as, pci->pci_displayname, pci->pci_displayname_sz, key) < 0 ) {
    PERSONA_UNREF(p);
    pthread_rwlock_unlock(&as->as_personas_mutex);
    return -1;
  }

  p->p_flags = pci->pci_flags;

  if ( persona_add_password(p, pci->pci_password, pci->pci_password_sz) < 0 ) {
    PERSONA_UNREF(p);
    pthread_rwlock_unlock(&as->as_personas_mutex);
    return -1;
  }

  if ( persona_add_token_security(p) < 0 ) {
    PERSONA_UNREF(p);
    pthread_rwlock_unlock(&as->as_personas_mutex);
    return -1;
  }

  if ( pci->pci_bump_avatar ) {
    if ( appstate_bump_persona_avatar(as, p) < 0 ) {
      PERSONA_UNREF(p);
      pthread_rwlock_unlock(&as->as_personas_mutex);
      return -1;
    }
  }

  if ( appstate_save_persona(as, p) < 0 ) {
    PERSONA_UNREF(p);
    pthread_rwlock_unlock(&as->as_personas_mutex);
    return -1;
  }

  HASH_ADD(p_hh, as->as_personas, p_persona_id, PERSONA_ID_LENGTH, p);

  pthread_rwlock_unlock(&as->as_personas_mutex);

  if ( ret_ptr ) {
    PERSONA_REF(p);
    *ret_ptr = p;
  }

  return 0;
}

int appstate_update_persona(struct appstate *as,
                            struct persona *p,
                            struct personacreateinfo *pci) {
  SAFE_RWLOCK_WRLOCK(&as->as_personas_mutex);

  if ( pci->pci_displayname ) {
    if ( persona_set_display_name(p, pci->pci_displayname, pci->pci_displayname_sz) < 0 )
      goto error;
  }

  if ( pci->pci_password ) {
    if ( persona_reset_password(p, pci->pci_password, pci->pci_password_sz) < 0 )
      goto error;
  }

  if ( pci->pci_bump_avatar ) {
    if ( appstate_bump_persona_avatar(as, p) < 0 )
      goto error;
  }

  if ( appstate_save_persona(as, p) < 0 )
    goto error;

  pthread_rwlock_unlock(&as->as_personas_mutex);

  return 0;

 error:
  pthread_rwlock_unlock(&as->as_personas_mutex);

  return -1;
}

int appstate_lookup_persona(struct appstate *as, const char *pid, struct persona **p) {
  struct persona *existing;
  *p = NULL;

  SAFE_RWLOCK_RDLOCK(&as->as_personas_mutex);
  HASH_FIND(p_hh, as->as_personas, pid, PERSONA_ID_LENGTH, existing);
  pthread_rwlock_unlock(&as->as_personas_mutex);

  if ( existing ) {
    PERSONA_REF(existing);
    *p = existing;
    return 0;
  } else {
    *p = NULL;
    return -1;
  }
}

int appstate_get_personaset(struct appstate *as, struct personaset **ps) {
  static const char *personas_hdr = "INTRUSTD PERSONAS\n";
  struct persona *cur_persona, *tmp_persona;
  int ret = 0;

  SAFE_RWLOCK_WRLOCK(&as->as_personas_mutex);

  if ( as->as_cur_personaset ) {
    PERSONASET_REF(as->as_cur_personaset);
    *ps = as->as_cur_personaset;
  } else {
    struct buffer b;
    const char *data;
    size_t data_sz;

    *ps = NULL;

    buffer_init(&b);

    buffer_write(&b, personas_hdr, strlen(personas_hdr));

    HASH_ITER(p_hh, as->as_personas, cur_persona, tmp_persona) {
      if ( persona_write_as_vcard(cur_persona, &b) < 0 ) {
        ret = -1;
        goto done;
      }
    }

    buffer_finalize(&b, &data, &data_sz);
    assert(data && data_sz);

    *ps = personaset_from_buf((const char *) data, data_sz);
    if ( !(*ps) ) {
      free((void *) data);
      ret = -1;
      goto done;
    }

    as->as_cur_personaset = *ps;
    PERSONASET_REF(*ps);
  }

 done:
  pthread_rwlock_unlock(&as->as_personas_mutex);
  return ret;
}

struct appupdater *appstate_queue_update_ex(struct appstate *as,
                                            const char *uri, size_t uri_len,
                                            const char *sign_uri, size_t sign_uri_len,
                                            int reason, int progress, struct app *app) {
  if ( pthread_rwlock_wrlock(&as->as_applications_mutex) == 0 ) {
    struct appupdater *ret;
    HASH_FIND(au_hh, as->as_updates, uri, uri_len, ret);
    if ( !ret ) {
      ret = appupdater_new(as, uri, uri_len, sign_uri, sign_uri_len, reason, progress, app);
      if ( ret ) {
        APPUPDATER_REF(ret);
        HASH_ADD_KEYPTR(au_hh, as->as_updates, ret->au_url, strlen(ret->au_url), ret);
        qdevtsub_init(&ret->au_completion_evt, OP_APPSTATE_APPLICATION_UPDATED, appstatefn);
        appupdater_request_event(ret, &ret->au_completion_evt);
      }
    }
    pthread_rwlock_unlock(&as->as_applications_mutex);
    return ret;
  } else
    return NULL;
}

struct app *appstate_get_app_by_url(struct appstate *as, const char *domain) {
  return appstate_get_app_by_url_ex(as, domain, strlen(domain));
}

struct app *appstate_get_app_by_url_ex(struct appstate *as, const char *domain, size_t cansz) {
  if ( pthread_rwlock_rdlock(&as->as_applications_mutex) == 0 ) {
    struct app *a;
    HASH_FIND(app_hh, as->as_apps, domain, cansz, a);
    if ( a )
      APPLICATION_REF(a);
    pthread_rwlock_unlock(&as->as_applications_mutex);
    return a;
  } else
    return NULL;
}

int appstate_install_app_from_manifest(struct appstate *as, struct appmanifest *mf) {
  struct app *existing;

  if ( pthread_rwlock_wrlock(&as->as_applications_mutex) == 0 ) {
    int ret = 0;
    HASH_FIND(app_hh, as->as_apps, mf->am_domain, strlen(mf->am_domain), existing);
    if ( existing ) {
      fprintf(stderr, "appstate_install_app_from_manifest: '%s' already exists\n", mf->am_domain);
      ret = -1;
    } else {
      struct app *a = application_from_manifest(mf);
      if ( !a ) {
        fprintf(stderr, "appstate_install_app_from_manifest: could not allocate app\n");
        ret = -1;
      } else {
        ret = appstate_update_app(as, a->app_domain, NULL, mf, 1);
        if ( ret == 0 ) {
          HASH_ADD_KEYPTR(app_hh, as->as_apps, a->app_domain, strlen(a->app_domain), a);
        }

        appstate_update_application_state(as, a);
      }
    }
    pthread_rwlock_unlock(&as->as_applications_mutex);
    return ret;
  } else
    return -1;
}

int appstate_update_app_from_manifest(struct appstate *as, struct app *a, struct appmanifest *mf) {
  if ( pthread_rwlock_wrlock(&as->as_applications_mutex) == 0 ) {
    int ret = 0;
    struct app *existing;
    struct appmanifest *old;

    HASH_FIND(app_hh, as->as_apps, mf->am_domain, strlen(mf->am_domain), existing);
    if ( !existing ) {
      fprintf(stderr, "appstate_update_from_manifest: '%s' does not exist\n", mf->am_domain);
      ret = -1;
    } else {
      ret = appstate_update_app(as, existing->app_domain, existing->app_current_manifest, mf, 0);
      APPLICATION_REF(existing);
    }

    fprintf(stderr, "Updating app %s to %s (manifest %p)\n", mf->am_domain, mf->am_nix_closure, mf);

    pthread_rwlock_unlock(&as->as_applications_mutex);

    if ( ret == 0 ) {
      if ( pthread_mutex_lock(&existing->app_mutex) == 0 ) {
        old = existing->app_current_manifest;
        existing->app_current_manifest = mf;
        APPMANIFEST_REF(mf);

        // Requests that the instances reset themselves
        application_request_instance_resets(&as->as_eventloop, existing);

        pthread_mutex_unlock(&existing->app_mutex);

        APPMANIFEST_UNREF(old);
      } else
        ret = -1;
      APPLICATION_UNREF(existing);
    }

    return ret;
  } else
    return -1;
}

static int check_signature(const EVP_MD *md, EVP_PKEY *key, FILE *mf,
                           const char *sig, size_t sig_len) {
  char buf[64];
  int ret;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if ( !ctx ) {
    fprintf(stderr, "check_signature: out of memory\n");
    return 0;
  }

  if ( !EVP_VerifyInit(ctx, md) ) {
    fprintf(stderr, "check_signature: EVP_VerifyInit fails\n");
    ERR_print_errors_fp(stderr);
    EVP_MD_CTX_free(ctx);
    return 0;
  }

  while ( !feof(mf) ) {
    int bytes_read;

    bytes_read = fread(buf, 1, sizeof(buf), mf);
    if ( bytes_read < sizeof(buf) ) {
      if ( ferror(mf) ) {
        EVP_MD_CTX_free(ctx);
        fprintf(stderr, "check_signature: error while reading manifest\n");
        return 0;
      }
    }

    if ( !EVP_VerifyUpdate(ctx, buf, bytes_read) ) {
      fprintf(stderr, "check_signature: EVP_VerifyUpdate fails\n");
      ERR_print_errors_fp(stderr);
      EVP_MD_CTX_free(ctx);
      return 0;
    }
  }

  ret = EVP_VerifyFinal(ctx, (const unsigned char *)sig, sig_len, key);
  if ( ret < 0 ) {
    fprintf(stderr, "check_signature: EVP_VerifyFinal fails\n");
    ERR_print_errors_fp(stderr);
    EVP_MD_CTX_free(ctx);
    return 0;
  }

  EVP_MD_CTX_free(ctx);

  return ret;
}

static int appstate_can_run_as_admin(struct appstate *as, struct app *a) {
  // In order to run as administrator, there needs to be a signing key
  // <mf-digest>.asc, containing the a signature by a trusted
  // authority of the application manifest.
  char mf_signature_path[PATH_MAX];
  char mf_digest_str[SHA256_DIGEST_LENGTH * 2 + 1];
  FILE *signature, *manifest;
  int err, i;

  void *sig_bytes;
  size_t sig_len;

  err = snprintf(mf_signature_path, sizeof(mf_signature_path),
                 "%s/manifests/%s.sign", as->as_conf_dir,
                 hex_digest_str(a->app_current_manifest->am_digest, mf_digest_str,
                                SHA256_DIGEST_LENGTH));
  if ( err >= sizeof(mf_signature_path) ) {
    fprintf(stderr, "appstate_can_run_as_admin: path overflow\n");
    return 0;
  }

  signature = fopen(mf_signature_path, "rt");
  if ( !signature ) {
    fprintf(stderr, "appstate_can_run_as_admin: no signature for manifest %s\n", mf_digest_str);
    return 0;
  }

  if ( fread_base64(signature, &sig_bytes, &sig_len) < 0 ) {
    fprintf(stderr, "appstate_can_run_as_admin: invalid base64 encoding of signature for %s\n",
            mf_digest_str);
    fclose(signature);
    return 0;
  }

  fclose(signature);

  err = snprintf(mf_signature_path, sizeof(mf_signature_path),
                 "%s/manifests/%s", as->as_conf_dir, mf_digest_str);
  if ( err >= sizeof(mf_signature_path) ) {
    fprintf(stderr, "appstate_can_run_as_admin: path overflow\n");
    return 0;
  }

  manifest = fopen(mf_signature_path, "rt");
  if ( !manifest ) {
    fprintf(stderr, "appstate_can_run_as_admin: could not find manifest for %s: %s\n", mf_digest_str, mf_signature_path);
    free(sig_bytes);
    return 0;
  }

  // Now verify the signature
  for ( i = 0; i < as->as_trusted_key_count; ++i ) {
    EVP_PKEY *trusted_key = as->as_trusted_keys[i];

    if ( fseek(manifest, 0, SEEK_SET) != 0 ) {
      fprintf(stderr, "appstate_can_run_as_admin: could not move to beginning of file\n");
      fclose(manifest);
      free(sig_bytes);
      return 0;
    }

    if ( check_signature(EVP_sha256(), trusted_key, manifest, sig_bytes, sig_len) ) {
      free(sig_bytes);
      fclose(manifest);
      return 1;
    }
  }

  fprintf(stderr, "Manifest for %s not verified because the signature was invalid\n", mf_digest_str);
  return 0;
}

static void appstate_update_root(struct appstate *as, struct appmanifest *am) {
  char path[PATH_MAX], closure_path[PATH_MAX];
  int err;
  pid_t child;

  err = snprintf(path, sizeof(path), "%s/nix-roots/%s",
                 as->as_conf_dir, am->am_domain);
  if ( err >= sizeof(path) ) {
    fprintf(stderr, "appstate_update_root: path overflow (for app %s)\n",
            am->am_domain);
    return ;
  }

  // Assume this is a link, or non-existent
  err = readlink(path, closure_path, sizeof(closure_path) - 1);
  if ( err < 0 ) {
    if ( errno != ENOENT ) {
      perror("appstate_update_root: readlink");
      return;
    }
  } else {
    SAFE_ASSERT(err < sizeof(closure_path));
    closure_path[err] = '\0';

    if ( strncmp(am->am_nix_closure, closure_path, err) == 0 ) {
      // Already okay
      return;
    } else {
      err = unlink(path);
      if ( err < 0 && errno != ENOENT ) {
        perror("appstate_update_root: unlink");
        return;
      }
    }
  }

  child = vfork();
  if ( child < 0 ) {
    perror("appstate_update_root: fork");
    return;
  }

  if ( child == 0 ) {
    execlp("nix-store", "nix-store", "--realise", am->am_nix_closure,
           "--add-root", path, "--indirect", NULL);
    exit(128);
  } else {
    int sts;

    err = waitpid(child, &sts, 0);
    if ( err <= 0 ) {
      perror("appstate_update_root: waitpid");
      return;
    }

    if ( sts != 0 ) {
      fprintf(stderr,
              "appstate_update_root: 'nix-store --realise %s --add-root %s --indirect' exited with %d\n",
             am->am_nix_closure, path, sts);
    }
  }
}

void appstate_update_application_state(struct appstate *as, struct app *a) {
  struct appmanifest *am;

  SAFE_MUTEX_LOCK(&a->app_mutex);
  a->app_flags &= ~(APP_FLAG_RUN_AS_ADMIN | APP_FLAG_SINGLETON | APP_FLAG_SIGNED);

  if ( (a->app_current_manifest->am_flags & APPMANIFEST_FLAG_RUN_AS_ADMIN) &&
       appstate_can_run_as_admin(as, a) ) {
    fprintf(stderr, "Requesting run as singleton or admin %p\n", a);
    a->app_flags |= APP_FLAG_SIGNED; // TODO allow any app to be signed

    if ( a->app_current_manifest->am_flags & APPMANIFEST_FLAG_RUN_AS_ADMIN )
      a->app_flags |= APP_FLAG_RUN_AS_ADMIN;
    if ( a->app_current_manifest->am_flags & APPMANIFEST_FLAG_SINGLETON )
      a->app_flags |= APP_FLAG_SINGLETON;

    // TODO manual autostart
    if ( strcmp(a->app_domain, ADMIN_APP_URL) == 0 ) {
      fprintf(stderr, "Setting as autostart %s\n", a->app_domain);
      a->app_flags |= APP_FLAG_AUTOSTART;
    }
  }

  if ( (a->app_current_manifest->am_flags & APPMANIFEST_FLAG_SINGLETON) &&
       appstate_check_app_permission(as, a, APP_PERMISSION_SINGLETON) )
    a->app_flags |= APP_FLAG_SINGLETON;

  if ( (a->app_current_manifest->am_flags & APPMANIFEST_FLAG_AUTOSTART) &&
       appstate_check_app_permission(as, a, APP_PERMISSION_AUTOSTART) )
    a->app_flags |= APP_FLAG_AUTOSTART;

  am = a->app_current_manifest;
  APPMANIFEST_REF(am);

  pthread_mutex_unlock(&a->app_mutex);

  appstate_update_root(as, am);

  APPMANIFEST_UNREF(am);
}

int appstate_log_path(struct appstate *as, const char *mf_digest_str, const char *extra,
                      char *out, size_t out_sz) {
  int n1, n2;

  n1 = snprintf(out, out_sz, "%s/logs/%s", as->as_conf_dir, mf_digest_str);
  if ( n1 >= out_sz ) return -1;

  if ( extra ) {
    n2 = snprintf(out + n1, out_sz - n1, "/%s", extra);
    if ( (n1 + n2) >= out_sz ) return -1;
  }
  return 0;
}

struct token *appstate_open_token_ex(struct appstate *as,
                                     const char *token_hex, size_t token_sz) {
  unsigned char exp_digest[TOKEN_ID_LENGTH];

  if ( token_sz != sizeof(exp_digest) * 2 ) {
    fprintf(stderr, "appstate_open_token_ex: invalid token name. Expected size %zu, got %zu\n",
            sizeof(exp_digest) * 2, token_sz);
    return NULL;
  }

  if ( !parse_hex_str(token_hex, exp_digest, sizeof(exp_digest)) ) {
    fprintf(stderr, "appstate_open_token_ex: invalid token name: %.*s\n",
            (int)(token_sz), token_hex);
    return NULL;
  }

  if ( pthread_mutex_lock(&as->as_tokens_mutex) == 0 ) {
    struct token *ret;
    HASH_FIND(tok_hh, as->as_tokens, exp_digest, sizeof(exp_digest), ret);
    if ( ret ) {
      TOKEN_REF(ret);
    } else {
      char path[PATH_MAX];

      if ( snprintf(path, sizeof(path), "%s/tokens/%.*s",
                    as->as_conf_dir, (int) token_sz, token_hex) >= sizeof(path) ) {
        fprintf(stderr, "appstate_open_token_ex: path overflow\n");
        ret = NULL;
      } else {
        FILE *token_file = fopen(path, "rb");
        if ( !token_file ) {
          perror("appstate_open_token_ex: fopen");
          ret = NULL;
        } else {
          if ( token_verify_hash(token_file, token_hex, token_sz) != 0 ) {
            fprintf(stderr, "appstate_open_token_ex: invalid hash\n");
            ret = NULL;
            fclose(token_file);
          } else {
            if ( fseek(token_file, 0, SEEK_SET) < 0 ) {
              perror("appstate_open_token_ex: fseek");
              ret = NULL;
              fclose(token_file);
            } else {
              ret = token_new_from_file(token_file);
              if ( ret ) {
                if ( memcmp(ret->tok_token_id, exp_digest, sizeof(exp_digest)) != 0 ) {
                  fprintf(stderr, "appstate_open_token_ex: token hash mismatch\n");
                  TOKEN_UNREF(ret);
                  ret = NULL;
                } else {
                  TOKEN_REF(ret);
                  HASH_ADD(tok_hh, as->as_tokens, tok_token_id, sizeof(ret->tok_token_id), ret);
                }
              }
              fclose(token_file);
            }
          }
        }
      }
    }
    pthread_mutex_unlock(&as->as_tokens_mutex);
    return ret;
  } else
    return NULL;
}

int appstate_check_app_permission(struct appstate *as, struct app *a, const char *perm_name) {
  char app_perms_nm[PATH_MAX], app_perm_line[4096];
  int err;
  FILE *perms_fp;
  size_t perm_len = strlen(perm_name);

  err = snprintf(app_perms_nm, sizeof(app_perms_nm), "%s/app.perms", as->as_conf_dir);
  if ( err >= sizeof(app_perms_nm) ) {
    fprintf(stderr, "appstate_check_app_permission: path overflow\n");
    return 0;
  }

  perms_fp = fopen(app_perms_nm, "rt");
  if ( !perms_fp ) {
    perror("appstate_check_app_permission: fopen");
    return 0;
  }

  fprintf(stderr, "appstate_check_app_permission: %s for %s\n",
          a->app_domain, perm_name);

  while ( fgets(app_perm_line, sizeof(app_perm_line), perms_fp) ) {
    int last_ix = strnlen(app_perm_line, sizeof(app_perm_line)) - 1;
    char *app_name, *cur_perm, *saveptr;
    if ( app_perm_line[last_ix] != '\n' && !feof(perms_fp) ) {
      fprintf(stderr, "appstate_check_app_permission: skipping long line (max length %zu)\n",
              sizeof(app_perm_line));
    }

    app_name = strtok_r(app_perm_line, " ", &saveptr);
    if ( !app_name ) {
      fprintf(stderr, "appstate_check_app_permission: malformed line\n");
    }

    if ( strncmp(app_name, a->app_domain, strlen(a->app_domain)) != 0 )
      continue;

    while ( ( cur_perm = strtok_r(NULL, " ", &saveptr) ) ) {
      if ( strncmp(cur_perm, perm_name, perm_len) == 0  ) {
        fclose(perms_fp);
        return 1;
      }
    }
  }

  fclose(perms_fp);
  return 0;
}

void init_appliance_global() {
  g_openssl_appstate_ix = SSL_CTX_get_ex_new_index(0, "appstate index", NULL, NULL, NULL);
  g_openssl_flock_data_ix = SSL_get_ex_new_index(0, "flock index", NULL, NULL, NULL);
  g_openssl_pconn_data_ix = SSL_get_ex_new_index(0, "pconn index", NULL, NULL, NULL);
}

int SSL_CTX_set_appstate(SSL_CTX *ctx, struct appstate *as) {
  return SSL_CTX_set_ex_data(ctx, g_openssl_appstate_ix, as);
}

struct appstate *SSL_CTX_get_appstate(SSL_CTX *ctx) {
  return SSL_CTX_get_ex_data(ctx, g_openssl_appstate_ix);
}

int SSL_set_flock(SSL *ssl, struct flock *f) {
  return SSL_set_ex_data(ssl, g_openssl_flock_data_ix, f);
}

struct flock *SSL_get_flock(SSL *ssl) {
  return SSL_get_ex_data(ssl, g_openssl_flock_data_ix);
}

int SSL_set_pconn(SSL *ssl, struct pconn *pc) {
  return SSL_set_ex_data(ssl, g_openssl_pconn_data_ix, pc);
}

struct pconn *SSL_get_pconn(SSL *ssl) {
  return SSL_get_ex_data(ssl, g_openssl_pconn_data_ix);
}

X509 *appstate_get_certificate(struct appstate *as) {
  X509 *ret = as->as_cert;
  X509_up_ref(ret);
  return ret;
}
