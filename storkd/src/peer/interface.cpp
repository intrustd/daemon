#include "interface.hpp"

namespace stork {
  namespace peer {
    InterfaceEnumerator::InterfaceEnumerator()
      : m_netlink_socket(-1) {
      m_netlink_socket = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
      if ( m_netlink_socket < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not create netlink socket: " << ec;
        return;
      }

      struct sockaddr_nl local;
      local.nl_family AF_NETLINK;
      local.nl_pad = 0;
      local.nl_pid = getpid();
      local.nl_groups = 0;

      int err = bind(nl_socket, (struct sockaddr *) &local, sizeof(local));
      if ( err < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not bind netlink socket: " << ec;
        close(m_netlink_socket);
        m_netlink_socket = -1;
        return;
      }
    }

    InterfaceEnumerator::~InterfaceEnumerator() {
      if ( m_netlink_socket > 0 )
        close(m_netlink_socket);
    }

    void InterfaceEnumerator::enumerate(std::list<boost::asio::ip::address> &ip, boost::system::error_code &ec) {
      // Get all interfaces
      struct {
        struct nlmsghdr hdr;
        struct ifinfomsg msg;
      } if_req;

      if_req.hdr.nlmsg_len = sizeof(if_req);
      if_req.hdr.nlmsg_type = RTM_GETLINK;
      if_req.hdr.nlmsg_flags = NLM_F_ACK;
      if_req.hdr.nlmsg_seq = 0;
      if_req.hdr.nlmsg_pid = getpid();

      if_req.msg.ifi_family = AF_UNSPEC;
      if_req.msg.ifi_type = 0;
      if_req.msg.ifi_index = 0;
      if_req.msg.ifi_flags = 0;
      if_req.msg.ifi_change = 0;

      send_nl_msg((struct nlmsghdr*)&if_req, ec);
      if ( ec ) return;

      // Now read all messages back
    }
  }
}

