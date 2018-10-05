#ifndef __appliance_configuration_H__
#define __appliance_configuration_H__

struct appconf {
  const char *ac_conf_dir;

  const char *ac_iproute_bin;
  const char *ac_ebroute_bin;

  const char *ac_kitepath;
  const char *ac_webrtc_proxy_path;
  const char *ac_persona_init_path;
  const char *ac_app_instance_init_path;

  uint32_t ac_flags;
};

// If set to 1, we do not use containers, as best we can
#define AC_FLAG_VALGRIND_COMPAT 0x1

#define AC_VALGRIND(ac) ((ac)->ac_flags & AC_FLAG_VALGRIND_COMPAT)

void appconf_init(struct appconf *c);
int appconf_parse_options(struct appconf *c, int argc, char **argv);
int appconf_validate(struct appconf *c, int do_debug);

#endif
