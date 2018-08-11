#ifndef __stork_peer_interface_HPP__
#define __stork_peer_interface_HPP__

#include <boost/asio.hpp>
#include <list>

namespace stork {
  namespace peer {
    /**
     * Class that can synchronously enumerate all linux interfaces and ip address
     */
    class InterfaceEnumerator {
    public:
      InterfaceEnumerator();
      ~InterfaceEnumerator();

      void enumerate(std::list<boost::asio::ip::address> &list, boost::system::error_code &ec);

    private:
      int m_netlink_socket;
      char m_receive_buffer[8192];

      std::vector<std::string> m_if_names;
    };
  }
}

#endif
