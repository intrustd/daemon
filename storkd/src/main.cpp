#include <boost/log/trivial.hpp>
#include <openssl/ssl.h>
#include <iostream>

#include "appliance.hpp"
#include "backend.hpp"
#include "container/runtime.hpp"
#include "container/init.hpp"
#include "peer/dtls.hpp"
#include "nix.hpp"

void usage () {
  std::cerr << "storkd - Stork appliance daemon" << std::endl;
  std::cerr << "Usage: storkd <storkd path>" << std::endl;
}

class MyInitializer : public stork::container::NamespacesInitializer {
protected:
  virtual void setup(stork::container::Namespaces &ns, int comm) {
    std::list< stork::container::UidMapping<uid_t> > users;
    std::list< stork::container::UidMapping<gid_t> > groups;

    users.push_back(stork::container::UidMapping<uid_t>(0, ns.init_data().root_uid, 1));
    groups.push_back(stork::container::UidMapping<gid_t>(0, ns.init_data().root_gid, 1));

    ns.setup_users(0, 0, users, groups);

    boost::filesystem::create_directories("./main-test/root");

    boost::filesystem::create_directories("./main-test/root/nix");
    boost::filesystem::create_directories("./main-test/root/proc");
    boost::filesystem::create_directories("./main-test/root/dev");
    boost::filesystem::create_directories("./main-test/root/sys");

    ns.mount("/nix", "./main-test/root/nix", "bind", stork::container::MountFlags().bind().rec().ro());
    ns.mount("proc", "./main-test/root/proc", "proc", stork::container::MountFlags());
    ns.mount("tmpfs", "./main-test/root/dev", "tmpfs",
             stork::container::MountFlags()
               .nosuid()
               .strictatime()
               .option("mode", "755")
               .option("size", "65536k"));
    boost::filesystem::create_directories("./main-test/root/dev/pts");
    boost::filesystem::create_directories("./main-test/root/dev/shm");
    boost::filesystem::create_directories("./main-test/root/dev/mqueue");
    ns.mount("devpts", "./main-test/root/dev/pts", "devpts",
             stork::container::MountFlags()
               .nosuid().noexec().option("newinstance")
               .option("ptmxmode", "0666").option("mode", "0620")
               .option("gid", "0")); // TODO figure out group id
    ns.mount("shm", "./main-test/root/dev/shm", "tmpfs",
             stork::container::MountFlags()
               .nosuid().noexec().nodev()
               .option("mode", "1777").option("size", "65536k"));
    ns.mount("mqueue", "./main-test/root/dev/mqueue", "mqueue",
             stork::container::MountFlags()
               .nosuid().noexec().nodev());
    ns.mount("sysfs", "./main-test/root/sys", "sysfs",
             stork::container::MountFlags()
               .nosuid().noexec().nodev().ro());

    // TODO this doesn't work
    boost::filesystem::create_directories("./main-test/root/sys/fs/cgroup");
    ns.mount("cgroup", "./main-test/root/sys/fs/cgroup", "cgroup",
             stork::container::MountFlags()
               .nosuid().noexec().nodev().relatime().ro().option("all"));

    ns.change_root("./main-test/root");

    ns.debug_mounts();
  }
};

int main(int argc, const char **argv) {
  if ( argc > 0 && strcmp(argv[0], "stork-init") == 0 ) {
    // Run as the init process
    BOOST_LOG_TRIVIAL(debug) << "Running as stork-init";
    stork::container::Init init(argc - 1, argv + 1);
    return init.run();
  } else if ( argc < 2 ) {
    usage();
    return 1;
  } else {
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    stork::peer::DTLSContext::setup_ssl();
    stork::peer::DTLSChannel::setup_ssl();

    BOOST_LOG_TRIVIAL(info) << "storkd starting";
    boost::filesystem::path config_path(argv[1]);

    try {
      stork::nix::NixStore nix;

      BOOST_LOG_TRIVIAL(debug) << "Building necessary nix pkgs";
      nix.build("iproute");

      BOOST_LOG_TRIVIAL(debug) << "Iproute path: " << nix["iproute"];

      boost::asio::io_service svc;
      stork::backend::FileBackend backend(svc, config_path);
      stork::appliance::Appliance appliance(svc, backend, nix, config_path);

      // We need to enter our own network namespace here to be able to do bridging and such
      // Create network namespace
      // Join network namespace using setns

      return appliance.run();
    } catch (const std::exception &e) {
      BOOST_LOG_TRIVIAL(error) << "storkd aborting: " << e.what();
      return 1;
    }
  }
}
