#ifndef __stork_container_runtime_HPP__
#define __stork_container_runtime_HPP__

#include <system_error>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/filesystem.hpp>

#include <sys/mount.h>
#include <linux/netlink.h>

#include "bridge.hpp"

namespace stork {
  namespace container {
    struct NamespaceInitializationData {
      pid_t abs_pid;
      uid_t root_uid;
      gid_t root_gid;
      BridgePort bridge_port;
      std::uint32_t ip_address;

      //      char stork_init_path[PATH_MAX];
    };

    template<typename Uid>
    class UidMapping {
    public:
      UidMapping(Uid container, Uid host, Uid count)
        : m_container(container), m_host(host), m_count(count) {
      }

      inline Uid container() const { return m_container; }
      inline Uid host() const { return m_host; }
      inline Uid count() const { return m_count; }

      inline void output(std::ostream &out) const {
        out << m_container << " " << m_host << " " << m_count << std::endl;
      }

    private:
      Uid m_container, m_host, m_count;
    };

    class MountFlags {
    public:
      inline MountFlags() : m_flags(0) { };

      inline const std::list<std::string> &options() const { return m_options; }
      inline unsigned long flags() const { return m_flags; }

      inline MountFlags &bind() { m_flags |= MS_BIND; return *this; }
      inline MountFlags &rec() { m_flags |= MS_REC; return *this; }
      inline MountFlags &remount() { m_flags |= MS_REMOUNT; return *this; }
      inline MountFlags &shared() { m_flags |= MS_SHARED; return *this; }
      inline MountFlags &private_() { m_flags |= MS_PRIVATE; return *this; }
      inline MountFlags &slave() { m_flags |= MS_SLAVE; return *this; }
      inline MountFlags &unbindable() { m_flags |= MS_UNBINDABLE; return *this; }

      inline MountFlags &noatime() { m_flags |= MS_NOATIME; return *this; }
      inline MountFlags &nodev() { m_flags |= MS_NODEV; return *this; }
      inline MountFlags &nodiratime() { m_flags |= MS_NODIRATIME; return *this; }
      inline MountFlags &noexec() { m_flags |= MS_NOEXEC; return *this; }
      inline MountFlags &nosuid() { m_flags |= MS_NOSUID; return *this; }
      inline MountFlags &ro() { m_flags |= MS_RDONLY; return *this; }
      inline MountFlags &relatime() { m_flags |= MS_RELATIME; return *this; }
      inline MountFlags &silent() { m_flags |= MS_SILENT; return *this; }
      inline MountFlags &sync() { m_flags |= MS_SYNCHRONOUS; return *this; }
      inline MountFlags &strictatime() { m_flags |= MS_STRICTATIME; return *this; }

      inline MountFlags &option(const std::string &option) {
        m_options.push_back(option);
        return *this;
      }

      inline MountFlags &option(const std::string &key,
                                const std::string &val) {
        std::stringstream opt;
        opt << key << "=" << val;
        option(opt.str());
        return *this;
      }

    private:

      unsigned long m_flags;
      std::list<std::string> m_options;
    };

    class TunConfigurator;

    class NetworkDevice {
    public:
      inline const std::string &device_name() const { return m_device_name; }

    protected:
      NetworkDevice(NetworkDevice &&device) =default;
      inline NetworkDevice(const std::string &ifname)
        : m_device_name(ifname) {
      };
      inline NetworkDevice() {};

      friend class Namespaces;

      inline void device_name(const std::string &nm) { m_device_name = nm; }

    private:
      std::string m_device_name;
    };

    class TunDevice : public NetworkDevice {
    public:
      TunDevice(const TunDevice &d) =delete;

      TunDevice(bool is_tap = false);
      TunDevice(TunDevice &&d);
      ~TunDevice();

      inline bool is_valid() const { return m_tun_fd > 0; }

      inline int tun_fd() const { return m_tun_fd; } // Use steal() if you want to transfer ownershi

      int steal();

    private:

      void open(bool is_tap);

      int m_tun_fd;
      std::string m_device_name;

      friend class Namespaces;
    };

    class IfaceConfigurator;

    class NetworkConfigurator {
    public:
      ~NetworkConfigurator();

      IfaceConfigurator operator () (const NetworkDevice &d);

      inline bool is_valid() const { return m_conf_fd > 0; }

    private:
      NetworkConfigurator();

      void open();

      void send_request(nlmsghdr *n);
      int recv_ack() const;

      friend class Namespaces;
      friend class IfaceConfigurator;

      int m_conf_fd;
      std::uint32_t m_msg_seq;
    };

    class IfaceConfigurator {
    public:
      IfaceConfigurator &add_address(const boost::asio::ip::address_v6 &v6, std::uint8_t prefix_len);
      IfaceConfigurator &bring_up();

    private:
      IfaceConfigurator(NetworkConfigurator &conf, const NetworkDevice &d);

      void open();

      void set_ifr_name(ifreq &ifr);

      NetworkConfigurator &m_net;
      const NetworkDevice &m_device;

      int m_if_index;

      friend class NetworkConfigurator;
    };

    class Namespaces {
    public:
      ~Namespaces();

      void hostname(const std::string &hn);
      void domain_name(const std::string &dn);

      void setup_users(uid_t reuid, gid_t regid,
                       const std::list< UidMapping<uid_t> > &users,
                       const std::list< UidMapping<gid_t> > &grps);
      void set_uid_gid(uid_t reuid, gid_t regid);

      void mount(const boost::filesystem::path &src,
                 const boost::filesystem::path &dest,
                 const std::string &type,
                 const MountFlags &options);
      void debug_mounts();
      void debug_routes();
      void debug_routes_v6();

      void change_root(const boost::filesystem::path &new_root);

      NetworkConfigurator network_configuration() const;
      NetworkDevice loopback_device() const;

      // std::shared_ptr<TunInterface> new_tun_interface()

      inline const NamespaceInitializationData &init_data() const { return m_init_data; }
      inline BridgePort bridge_port() const { return init_data().bridge_port; }
      inline boost::asio::ip::address_v4 ip() const { return boost::asio::ip::address_v4(init_data().ip_address); }

    private:
      Namespaces(const NamespaceInitializationData &ni_data,
                 const boost::filesystem::path &proc_path);

      void close_ns_fd(int fd);
      int open_ns(const boost::filesystem::path &path);

      BridgePort m_port;

      friend class NamespacesInitializer;

      NamespaceInitializationData m_init_data;
    };

    enum namespace_errc_t {
      namespace_already_initializing = 1,
      namespace_system_error = 2
    };
    const std::error_category& namespace_error_category();

    int ns_trampoline(void *d);
    class NamespacesInitializer {
    public:
      NamespacesInitializer(std::size_t stack_sz = (1024 * 1024));
      ~NamespacesInitializer();

      void async_setup_namespaces(BridgeController &c,
                                  std::function<void(std::error_code, pid_t, int)> cb);

    protected:
      virtual void setup(Namespaces &ns, int comm);

    private:
      void do_setup();

      std::atomic_bool m_is_setting_up;
      int m_ipc_sockets[2];

      std::vector<std::uint8_t> m_stack;

      friend int ns_trampoline(void *);
    };
  }
}

namespace std {
  template<>
  struct is_error_code_enum<stork::container::namespace_errc_t>
    : public std::true_type {};

  inline std::error_code make_error_code(stork::container::namespace_errc_t e) {
    return std::error_code(static_cast<int>(e),
                           stork::container::namespace_error_category());
  }
}

#endif
