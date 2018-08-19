#ifndef __stork_container_persona_HPP__
#define __stork_container_persona_HPP__

#include <string>
#include <boost/asio.hpp>
#include <boost/process/child.hpp>

#include "../backend.hpp"
#include "../queue.hpp"
#include "runtime.hpp"
#include "bridge.hpp"

namespace stork {
  namespace container {
    /**
     * A persona container is a container for running various proxy
     * services that need to be run within the IP address assigned to
     * a given persona.
     *
     * Unlike an application container, the init process here is quite
     * simple. It simply waits on SIGCHLD and runs wait as necessary.
     */
    class PersonaContainer : public NamespacesInitializer {
    public:
      PersonaContainer(boost::asio::io_service &svc, BridgeController &bridge, const backend::PersonaId &persona);
      ~PersonaContainer();

      void async_after_launch(std::function<void(std::error_code)> cb);

      void async_launch_webrtc_proxy(std::function<void(std::error_code, BridgeController::UsedUdpPort &&p)> completion);

      // Only valid within the callback of async_after_launch
      const boost::asio::ip::address_v4 &ip() const { return m_our_ip; }

    private:
      /**
       * Asynchronously launches the container and calls cb on
       * completion.
       *
       * No other thread should read or write any member variable
       * until cb is called
       */
      void async_launch(std::function<void(std::error_code)> cb);

      /**
       * The setup method for PersonaContainer will remount the root
       * filesystem as read only, set up a basic user name mapping,
       * and run an init process
       *
       * It will send the current network namespace over comm to the
       * parent process, and wait for a message on comm, signaling
       * that it's ethernet connection has been established.
       *
       * It will then run an init process, persona-init
       */
      virtual void setup(Namespaces &ns, int comm) override;

      BridgeController &m_bridger;
      backend::PersonaId m_persona_id;

      stork::util::queue m_setup_queue;
      bool m_is_setup;

      /**
       * Appliance end of a unix socket that can be used to
       * communicate with the persona-init process. This can be used
       * to launch applications within the container
       */
      int m_comm_fd;

      boost::asio::ip::address_v4 m_our_ip;

      // TODO figure out how to wait on this
      boost::process::child m_init_process;

      BridgeController::Capability m_capability;
    };
  }
}

#endif
