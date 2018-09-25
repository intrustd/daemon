#ifndef __stork_container_bridge_HPP__
#define __stork_container_bridge_HPP__

#include <array>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/asio.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/shared_mutex.hpp>
#include <net/ethernet.h>

#include "../nix.hpp"
#include "../backend.hpp"
#include "../application/application.hpp"
#include "../crypto/certificate.hpp"

namespace stork {
  namespace container {
    class IUdpListener {
    public:
      virtual void on_udp_packet(const boost::asio::ip::address_v4 &saddr,
                                 std::uint16_t sport, std::uint16_t dport,
                                 const boost::asio::const_buffer &b) =0;
    };

    class BridgePort {
    public:
      BridgePort(const BridgePort &port) =default;
      inline BridgePort() : port(-1) { }

    private:
      inline BridgePort(int which) : port(which) { }

      int port;
      friend class BridgeController;
    };

    class Manager;

    class BridgeController {
    public:
      BridgeController(boost::asio::io_service &svc, nix::NixStore &nix,
                       Manager &cmgr, backend::IBackend &be);
      ~BridgeController();

      static constexpr uint16_t STORKD_INTERNAL_UDP_PORT = 9998;

      // Sets up networking in this namespace
      std::error_code set_up_networking();

      using ArpEntry = std::pair< std::uint32_t, std::array<std::uint8_t, ETH_ALEN> >;
      BridgePort allocate_port();
      boost::asio::ip::address_v4 allocate_ip();

      std::error_code create_veth_to_ns(int netns_fd, BridgePort port_ix,
                                        const boost::asio::ip::address_v4 &this_ip,
                                        const std::string &if_name, ArpEntry &new_entry);

      void send_arp_entry_over_socket(int comm, const ArpEntry &arp);
      ArpEntry add_arp_from_socket(int comm);

      inline int userns_fd() const { return m_userns_fd; }

      inline void enable_logging(std::fstream &&f) {
        boost::unique_lock l(m_dbg_mutex);
        m_eth_debug = std::move(f);

        m_eth_debug.imbue(std::locale(std::cout.getloc(),
                                      new boost::posix_time::time_facet("%H:%M:%S%F")));
      }

      std::array<std::uint8_t, ETH_ALEN> lookup_arp(const boost::asio::ip::address_v4 &v4,
                                                    bool &found);
      void add_arp_entry(const boost::asio::ip::address_v4 &v4,
                         const std::array<std::uint8_t, ETH_ALEN> &hw_addr);

      class UsedUdpPort {
      public:
        UsedUdpPort(BridgeController &b);
        UsedUdpPort(UsedUdpPort &&pt);
        ~UsedUdpPort();

        inline bool is_valid() const { return m_port != 0; }
        inline operator bool() const { return is_valid(); }

        inline std::uint16_t port() const { return m_port; }
        void listen(IUdpListener *listener);

        void write_pkt(const boost::asio::ip::address_v4 &a_dst, std::uint16_t p_dst, const boost::asio::const_buffer &b);

      private:
        UsedUdpPort(BridgeController &c, std::uint16_t p);

        BridgeController &m_controller;
        std::uint16_t m_port;

        friend class BridgeController;
      };
      UsedUdpPort use_udp_port(std::uint16_t port = 0);

      using Capability = std::string;
      Capability persona_capability(const backend::PersonaId &pid);
      Capability app_instance_capability(const backend::PersonaId &pid,
                                         const application::ApplicationIdentifier &app_id);

    private:
      static std::array<std::uint8_t, ETH_ALEN> find_hw_addr(const std::string &ifn, std::error_code &ec);

      void sign_capability(std::string &cap);
      void set_udp_listener(std::uint16_t port, IUdpListener *l);
      IUdpListener *find_udp_listener(std::uint16_t port);
      void release_udp(std::uint16_t port);
      void write_udp_packet(std::uint16_t sport, std::uint16_t dport,
                            const boost::asio::ip::address_v4 &a_dst,
                            const boost::asio::const_buffer &b);

      int enter_network_namespace();
      int create_veth(const std::string &in_if_name, const std::string &out_if_name);
      int move_if_to_ns(const std::string &if_name, int netns_fd);

      boost::asio::ip::address_v4 next_ip();
      void read_tap(std::size_t mtu);
      void on_packet_read(boost::system::error_code ec, std::size_t sz);
      void handle_arp(void *arp_buf, std::size_t arp_buf_sz);
      void handle_ip(void *ip_buf, std::size_t ip_buf_sz);

      void write_raw_tap_pkt(void *buf, std::size_t sz);
      void log_outgoing_pkt(void *buf, std::size_t sz);
      void log_incoming_pkt(void *buf, std::size_t sz);

      template<typename T>
      void write_tap_pkt(const T &t) { write_raw_tap_pkt((void *) &t, sizeof(t)); }

      static int main(void *comm);

      boost::asio::io_service &m_service;
      nix::NixStore &m_nix_store;
      Manager &m_container_mgr;
      backend::IBackend &m_backend;

      std::string m_cap_key;

      boost::shared_mutex m_dbg_mutex;
      std::fstream m_eth_debug;

      int m_netns_fd, m_userns_fd;
      boost::asio::ip::address_v4 m_tap_addr, m_bridge_addr;
      std::array<std::uint8_t, ETH_ALEN> m_stork_mac;
      boost::asio::posix::stream_descriptor m_tap_stream;
      std::vector<std::uint8_t> m_tap_buf;

      boost::shared_mutex m_arp_mutex;
      std::unordered_map< std::uint32_t, std::array<std::uint8_t, ETH_ALEN> > m_arp_table;

      boost::shared_mutex m_udp_mutex;
      std::unordered_map<std::uint16_t, IUdpListener *> m_udp_ports;

      boost::shared_mutex m_veth_mutex;
      int m_eth_ix;
      std::uint32_t m_next_ip;

      friend class UsedUdpPort;
      friend class AppInstanceResolver;
    };
  }
}

#endif
