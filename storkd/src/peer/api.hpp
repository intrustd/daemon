#ifndef __stork_peer_api_HPP__
#define __stork_peer_api_HPP__

#include <boost/log/trivial.hpp>
#include <boost/log/utility/manipulators/dump.hpp>
#include <boost/asio.hpp>

#include <memory>

namespace stork {
  namespace peer {
    template<typename Acceptor>
    class PeerApiServer;

    template<typename Socket>
    class PeerApiConnection : public std::enable_shared_from_this< PeerApiConnection<Socket> > {
    public:
      using api_server_type = PeerApiServer< typename Socket::protocol_type::acceptor_type > ;
      PeerApiConnection(std::shared_ptr< api_server_type > api, Socket s)
        : m_api_server(api), m_socket(std::move(s)) {
      }

      void start() {
        auto shared(this->shared_from_this());
        m_socket.async_recv_msg([shared] (boost::system::error_code ec, const auto &msg) {
            if ( ec ) {
              BOOST_LOG_TRIVIAL(error) << "PeerApiConnection: error receiving message: " << ec;
            } else {
              BOOST_LOG_TRIVIAL(debug) << "PeerApiConnection: received message: "
                                       << boost::log::dump(msg.data(), msg.size());

              shared->start();
            }
          });
      }

    private:
      std::shared_ptr<api_server_type> m_api_server;
      Socket m_socket;
    };

    template<typename Acceptor>
    class PeerApiServer : public std::enable_shared_from_this< PeerApiServer<Acceptor> > {
    public:
      PeerApiServer(Acceptor &&s)
        : m_socket(std::move(s)) {
        m_socket.listen(5);
      }

      void start() {
        auto shared(this->shared_from_this());
        m_socket.async_accept([shared] ( boost::system::error_code ec, typename Acceptor::protocol_type::socket_type s ) {
            if ( ec ) {
              BOOST_LOG_TRIVIAL(error) << "PeerApiServer: error accepting connection";
            } else {
              BOOST_LOG_TRIVIAL(debug) << "PeerApiServer: Accepted connection";

              std::make_shared< PeerApiConnection<typename Acceptor::protocol_type::socket_type> >(shared, std::move(s))->start();

              shared->start();
            }
          });
      }

    private:
      Acceptor m_socket;
    };
  }
}

#endif
