#include <unistd.h>
#include <sstream>
#include <init_proto.h>

#include "../util/fd.hpp"
#include "persona.hpp"

namespace stork {
  namespace container {
    std::error_code run_in_container(int comm_fd, std::vector<const char *> argv, std::vector<const char *> envv) {
      std::vector<std::uint8_t> buf;
      buf.resize(sizeof(struct stkinitmsg) +
                 std::accumulate(argv.begin(), argv.end(), 0,
                                 [] ( std::size_t cur, const char *s ) {
                                    return cur + strlen(s) + 1;
                                 }) +
                 std::accumulate(envv.begin(), envv.end(), 0,
                                 [] ( std::size_t cur, const char *s ) {
                                    return cur + strlen(s) + 1;
                                 }));

      struct stkinitmsg *pkt((struct stkinitmsg*) buf.data());
      pkt->sim_req = STK_REQ_RUN;
      pkt->sim_flags = 0;
      pkt->un.run.argc = argv.size();
      pkt->un.run.envc = envv.size();

      char *out(STK_ARGS(pkt));
      for ( const char *arg: argv ) {
        std::size_t sz(strlen(arg) + 1);
        std::copy(arg, arg + sz, out);
        out += sz;
      }

      for ( const char *env: envv ) {
        std::size_t sz(strlen(env) + 1);
        std::copy(env, env + sz, out);
        out += sz;
      }

      int err = send(comm_fd, buf.data(), buf.size(), 0);
      if ( err == -1 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not send run command to init process: " << ec;
        return std::error_code(ec, std::generic_category());
      }

      // TODO wait for response
      pid_t sts;
      err = recv(comm_fd, &sts, sizeof(sts), 0);
      if ( err == -1 ) {
         auto ec(errno);
         BOOST_LOG_TRIVIAL(error) << "Could not receive run status: " << ec;
         return std::error_code(ec, std::generic_category());
      }

      if ( sts < 0 ) {
        BOOST_LOG_TRIVIAL(error) << "Could not run process in persona container: " << (-sts);
        return std::error_code(-sts, std::generic_category());
      } else // TODO do we want to return the PID?
        return std::error_code();
    }

    PersonaContainer::PersonaContainer(boost::asio::io_service &svc,
                                       BridgeController &bridge,
                                       const backend::PersonaId &persona)
      : m_bridger(bridge), m_persona_id(persona),
        m_setup_queue(svc), m_is_setup(false), m_comm_fd(0) {
      m_capability = bridge.persona_capability(persona);
    }

    PersonaContainer::~PersonaContainer() {
      BOOST_LOG_TRIVIAL(debug) << "Killing persona container";
      m_setup_queue.purge_all();
      if ( m_comm_fd ) close(m_comm_fd);

      std::error_code ec;
      if ( m_init_process.running(ec) ) {
        BOOST_LOG_TRIVIAL(info) << "Terminating init process for persona container " << m_persona_id.id();
        m_init_process.terminate();
      }

      if ( ec ) {
        BOOST_LOG_TRIVIAL(error) << "Could not check if persona init process was running: " << ec;
      }
    }

    void PersonaContainer::async_launch_webrtc_proxy(std::function<void(std::error_code, BridgeController::UsedUdpPort &&)> cb) {
      async_after_launch([this, cb{std::move(cb)}] ( std::error_code ec ){
          if ( ec ) {
            BridgeController::UsedUdpPort invalid(m_bridger);
            cb(ec, std::move(invalid));
          } else {
            auto udp_port(m_bridger.use_udp_port());

            std::stringstream udp_port_s;
            udp_port_s << udp_port.port();
            std::vector<const char *> argv{
              "/home/tathougies/Projects/stork-cpp/webrtc-proxy/webrtc-proxy",
              "webrtc-proxy", udp_port_s.str().c_str(),
              m_capability.c_str()
            };

            ec = run_in_container(m_comm_fd, argv, std::vector<const char *>());

            cb(ec, std::move(udp_port));
          }
        });
    }

    void PersonaContainer::async_launch(std::function<void(std::error_code)> cb) {
      async_setup_namespaces(m_bridger,
        [this, cb{std::move(cb)}] (std::error_code ec, pid_t p, int comm) {
          BOOST_LOG_TRIVIAL(debug) << "async launch: " << ec;
          if ( ec ) {
            cb(ec);
          } else {
            // Receive arp entry from socket
            BridgeController::ArpEntry arp_entry(m_bridger.add_arp_from_socket(comm));

            std::uint8_t sts;
            int err = recv(comm, &sts, 1, 0);
            if ( err == -1 ) {
              ec = std::error_code(errno, std::generic_category());
              BOOST_LOG_TRIVIAL(error) << "Could not fetch status from init process: " << ec;
              cb(ec);
            } else {
              m_comm_fd = comm;
              m_our_ip = boost::asio::ip::address_v4(arp_entry.first);
              m_init_process = boost::process::child(p);

              cb(std::error_code());
            }
          }
        });
    }

    void PersonaContainer::async_after_launch(std::function<void(std::error_code)> cb) {
      m_setup_queue.post([this, cb{std::move(cb)}] (auto reason) {
          BOOST_LOG_TRIVIAL(debug) << "Async after launch: " << (reason.normal() ? "normal" : "canceled");
          if ( reason.normal() ) {
            if ( m_comm_fd ) {
              m_setup_queue.async_restart();
              cb(std::error_code());
            } else {
              BOOST_LOG_TRIVIAL(info) << "launching container";
              async_launch([this, cb{std::move(cb)}] (std::error_code ec) {
                  m_setup_queue.async_restart();
                  cb(ec);
                });
            }
          } else
            m_setup_queue.async_restart();
            cb(std::make_error_code(std::errc::operation_canceled));
        });
    }

    void PersonaContainer::setup(Namespaces &ns, int comm) {
//      std::list< UidMapping<uid_t> > users{
//        UidMapping<uid_t>(0, ns.init_data().root_uid, 1)
//      };
//
//      std::list< UidMapping<gid_t> > groups{
//        UidMapping<gid_t>(0, ns.init_data().root_gid, 1)
//      };
//
//      ns.setup_users(0, 0, users, groups);
      ns.set_uid_gid(0, 0);

      std::stringstream hostname;
      hostname << "persona-" << m_persona_id.id();
      ns.hostname(hostname.str());
      ns.domain_name("stork");

      // Now send network namespace to parent
      int netns_fd(open("/proc/self/ns/net", 0));
      if ( netns_fd < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not open network namespace: " << ec;
        return;
      }

      // Attempt to create veth ourselves
      m_bridger.set_up_networking();
      BridgeController::ArpEntry arp_entry;
      m_bridger.create_veth_to_ns(netns_fd, ns.bridge_port(), ns.ip(), "eth0", arp_entry);

      // Send arp entry on socket
      m_bridger.send_arp_entry_over_socket(comm, arp_entry);

      BOOST_LOG_TRIVIAL(info) << "Within container, we are listing network devices";
      system("ifconfig -a");

      BOOST_LOG_TRIVIAL(info) << "Persona container routes";
      system("route");

      BOOST_LOG_TRIVIAL(debug) << "Launching socat";
      //      system("ping 10.0.0.1");

      int err = dup2(comm, 3);
      if ( err == -1 ) {
        BOOST_LOG_TRIVIAL(error) << "Could not duplicate comm as 3";
      }

      close(comm);

      // Now run the persona-init process
      execlp("/home/tathougies/Projects/stork-cpp/init/persona-init",
             "persona-init", m_persona_id.id().c_str(), NULL);
      BOOST_LOG_TRIVIAL(error) << "Could not launch socat";
    }
  }
}
