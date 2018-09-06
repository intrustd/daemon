#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
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

#define OP_APPSTATE_ACCEPT_LOCAL EVT_CTL_CUSTOM
#define OP_APPSTATE_SAVE_FLOCK   (EVT_CTL_CUSTOM + 1)

int g_openssl_appstate_ix;
int g_openssl_flock_data_ix;

static int appstate_certificate_digest(X509 *cert, unsigned char *digest) {
  EVP_PKEY *pubkey = NULL;
  unsigned char *pubkey_raw = NULL;
  int err;

  pubkey = X509_get_pubkey(cert);
  cert = NULL;
  if ( !pubkey ) {
    fprintf(stderr, "appstate_certificate_digest: No public key in SSL certificate\n");
    return -1;
  }

  err = i2d_PublicKey(pubkey, &pubkey_raw);
  if ( err < 0 ) {
    fprintf(stderr, "appstate_certificate_digest: Could not write public key in DER format\n");
    return -1;
  }

  assert(pubkey_raw);
  FLOCK_SIGNATURE_METHOD(pubkey_raw, err, digest);

  free(pubkey_raw); // TODO is this the right thing to do ?

  return 0;
}

static int appstate_verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
  X509 *cert;
  SSL *ssl;
  int err, depth;

  struct flock *f;

  cert = X509_STORE_CTX_get_current_cert(ctx);
  err = X509_STORE_CTX_get_error(ctx);
  depth = X509_STORE_CTX_get_error_depth(ctx);

  ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());

  f = SSL_get_flock(ssl);
  if ( !f ) {
    fprintf(stderr, "appstate_verify_callback: no flock given\n");
    return 0;
  }

  fprintf(stderr, "Certificate depth %d\n", depth);

  if ( depth > FLOCK_MAX_CERT_DEPTH )
    return 0;

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
      fprintf(stderr, "appstate_verify_callback: success\n");
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

  fprintf(stderr, "appstate_verify_callback: unsure how to handle verification\n");
  return 0;
}

static void appstate_add_flock(struct appstate *st, char *flock_line) {
  char flocks_path[PATH_MAX];
  FILE *flocks;

  int err;

  err = snprintf(flocks_path, sizeof(flocks_path), "%s/flocks", st->as_conf_dir);
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
    fprintf(stderr, "   openssl ecparam -name secp256k1 -genkey -noout -out %s\n\n", app_key_nm);
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

  err = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"Kite Appliances", -1, -1, 0);
  if ( !err ) goto openssl_error;

  if ( !X509_set_issuer_name(as->as_cert, name) ) goto openssl_error;

  if ( !X509_sign(as->as_cert, as->as_privkey, EVP_sha1()) ) goto openssl_error;

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

    assert(RAND_bytes((unsigned char *)&ix, sizeof(ix)));

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
  err = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/" KITE_LOCAL_API_SOCK, ac->ac_conf_dir);
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

static int appstate_create_dtls_ctx(struct appstate *as) {
  int err;

  as->as_dtls_ctx = SSL_CTX_new(DTLS_client_method());
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

  SSL_CTX_set_verify(as->as_dtls_ctx, SSL_VERIFY_PEER,
                     appstate_verify_callback);

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

  err = persona_init_fp(p, persona_fp);
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
    perror("appstate_open_personas: could not read personas directory");
    return -1;
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

  err = snprintf(flocks_path, sizeof(flocks_path), "%s/flocks", as->as_conf_dir);
  if ( err >= sizeof(flocks_path) ) {
    fprintf(stderr, "appstate_open_flocks: buffer overflow while writing path\n");
    return -1;
  }

  flocks = fopen(flocks_path, "rt");
  if ( !flocks ) {
    fprintf(stderr, "appstate_open_flocks: Could not read flocks file\n");
    return 0;
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

void appstate_clear(struct appstate *as) {
  as->as_appliance_name[0] = '\0';
  as->as_conf_dir = NULL;
  as->as_mutexes_initialized = 0;
  as->as_cert = NULL;
  as->as_privkey = NULL;
  as->as_dtls_ctx = NULL;
  as->as_flocks = NULL;
  as->as_personas = NULL;
  as->as_cur_personaset = NULL;
  as->as_apps = NULL;
  as->as_local_fd = 0;
  fdsub_clear(&as->as_local_sub);
  bridge_clear(&as->as_bridge);
  eventloop_clear(&as->as_eventloop);
}

int appstate_setup(struct appstate *as, struct appconf *ac) {
  int err;

  appstate_clear(as);

  as->as_conf_dir = ac->ac_conf_dir;

  err = mkdir_recursive(ac->ac_conf_dir);
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

  if ( appstate_open_flocks(as, ac) < 0 )
    goto error;

  if ( appstate_open_personas(as, ac) < 0 )
    goto error;

  if ( !(AC_VALGRIND(ac)) ) {
    err = bridge_init(&as->as_bridge, ac->ac_iproute_bin);
    if ( err < 0 ) {
      fprintf(stderr, "appstate_setup: bridge_init failed\n");
      goto error;
    }
  }

  return 0;

 error:
  appstate_release(as);
  return -1;
}

void appstate_release(struct appstate *as) {
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

  // TODO release flocks, personas, and applications

  if ( as->as_cur_personaset ) {
    PERSONASET_UNREF(as->as_cur_personaset);
    as->as_cur_personaset = NULL;
  }
}

static void appstatefn(struct eventloop *el, int op, void *arg) {
  struct appstate *as = APPSTATE_FROM_EVENTLOOP(el);
  //  struct fdevent *fde;
  struct qdevent *qde;
  struct flock *flk;
  int new_sk;

  char flock_line[1024];
  unsigned char pk_digest[FLOCK_SIGNATURE_DIGEST_SZ];

  switch ( op ) {
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

    eventloop_subscribe_fd(el, as->as_local_fd, &as->as_local_sub);

    return;

  case OP_APPSTATE_SAVE_FLOCK:
    qde = (struct qdevent *)arg;
    flk = STRUCT_FROM_BASE(struct flock, f_on_should_save, qde->qde_sub);

    assert( pthread_mutex_lock(&flk->f_mutex) == 0 );
    fprintf(stderr, "Request to save flock %s\n", flk->f_uri_str);

    if ( appstate_format_flock_line(flk, flock_line, sizeof(flock_line), pk_digest) == 0 ) {
      memcpy(flk->f_expected_digest, pk_digest, sizeof(flk->f_expected_digest));
      flk->f_flags |= FLOCK_FLAG_VALIDATE_CERT;
      pthread_mutex_unlock(&flk->f_mutex);

      assert(pthread_rwlock_wrlock(&as->as_flocks_mutex) == 0);
      appstate_add_flock(as, flock_line);
      pthread_rwlock_unlock(&as->as_flocks_mutex);
    } else {
      pthread_mutex_unlock(&flk->f_mutex);
      fprintf(stderr, "appstatefn: overflow while trying to save flock\n");
    }

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
  FDSUB_SUBSCRIBE(&as->as_local_sub, FD_SUB_ACCEPT);
  eventloop_subscribe_fd(&as->as_eventloop, as->as_local_fd, &as->as_local_sub);
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
                            const char *display_name, int display_name_sz,
                            const char *password, int password_sz,
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

  if ( persona_init(p, display_name, display_name_sz, key) < 0 ) {
    PERSONA_UNREF(p);
    pthread_rwlock_unlock(&as->as_personas_mutex);
    return -1;
  }

  if ( persona_add_password(p, password, password_sz) < 0 ) {
    PERSONA_UNREF(p);
    pthread_rwlock_unlock(&as->as_personas_mutex);
    return -1;
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

int appstate_lookup_persona(struct appstate *as, const char *pid, struct persona **p) {
  struct persona *existing;
  *p = NULL;

  assert( pthread_rwlock_rdlock(&as->as_personas_mutex) == 0 );
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
  static const char *kite_personas_hdr = "KITE PERSONAS\n";
  struct persona *cur_persona, *tmp_persona;
  int ret = 0;

  assert( pthread_rwlock_wrlock(&as->as_personas_mutex) == 0 );

  if ( as->as_cur_personaset ) {
    PERSONASET_REF(as->as_cur_personaset);
    *ps = as->as_cur_personaset;
  } else {
    struct buffer b;
    const char *data;
    size_t data_sz;

    *ps = NULL;

    buffer_init(&b);

    buffer_write(&b, kite_personas_hdr, strlen(kite_personas_hdr));

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

void init_appliance_global() {
  g_openssl_appstate_ix = SSL_CTX_get_ex_new_index(0, "appstate index", NULL, NULL, NULL);
  g_openssl_flock_data_ix = SSL_get_ex_new_index(0, "flock index", NULL, NULL, NULL);
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

X509 *appstate_get_certificate(struct appstate *as) {
  X509 *ret = as->as_cert;
  X509_up_ref(ret);
  return ret;
}
