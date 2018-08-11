#ifndef __stork_websocket_HPP__
#define __stork_websocket_HPP__

#include <boost/asio.hpp>
#include <boost/beast.hpp>

#include "proto.hpp"

namespace stork {
  template<class NextLayer>
  class websocket {
  public:
    class acceptor;

    using endpoint = typename NextLayer::endpoint;

    class socket : public boost::beast::websocket::stream<typename NextLayer::socket> {
    public:
      socket(socket &&s) = default; //{
        //        : boost::beast::websocket::stream<typename NextLayer::socket>(std::move(s)) {
      //      }
      socket(typename NextLayer::socket &&s)
        : boost::beast::websocket::stream<typename NextLayer::socket>(std::move(s)) {
      }
      socket(boost::asio::io_service &svc)
        : boost::beast::websocket::stream<typename NextLayer::socket>(svc) {
      }

      template<typename ConnectHandler>
      void async_connect(const typename NextLayer::endpoint &ep, ConnectHandler &&h) {
        this->next_layer().async_connect
          (ep, [ep, this, h{std::move(h)}](boost::system::error_code ec) {
            if ( ec ) h(ec);
            else {
              std::stringstream address_buf;
              address_buf << ep.address();

              this->async_handshake(address_buf.str(),
                                    "/", // TODO allow us to set a target
                                    [this, h{std::move(h)}](boost::system::error_code ec) {
                                      this->binary(true);
                                      h(ec);
                                    });
            }
          });
      };

//      template<typename ...Args>
//      socket(Args&&... args)
//        : boost::beast::websocket::stream<typename NextLayer::socket>(std::forward<Args>(args)...) {
//      }

      using protocol_type = ::stork::websocket<NextLayer>;
      using endpoint_type = typename NextLayer::endpoint;

    };

    class acceptor {
    public:
      acceptor(acceptor &&s) =default;

      template<typename ...Args>
      acceptor(Args&&... args)
        : m_next_acceptor(args...) {
      }

      template<class AcceptHandler>
      void async_accept(AcceptHandler &&handler) {
        m_next_acceptor.async_accept
          ([handler{std::move(handler)}]
           (boost::system::error_code ec,
            typename NextLayer::socket s) {
            std::shared_ptr<socket> ws(std::make_shared<socket>(std::move(s)));
            if ( ec ) {
              handler(ec, std::move(*ws));
            } else {
              ws->async_accept([ws, handler{std::move(handler)}](boost::system::error_code ec) {
                  ws->binary(true);
                  handler(ec, std::move(*ws));
                });
            }
          });
      };

      typename NextLayer::endpoint local_endpoint() const {
        return m_next_acceptor.local_endpoint();
      }

      using endpoint_type = typename NextLayer::endpoint;
      using protocol_type = ::stork::websocket<NextLayer>;

    private:
      typename NextLayer::acceptor m_next_acceptor;
    };
  };

  namespace proto {
    template<typename NextLayer>
    class ProtocolProperties< stork::websocket<NextLayer> > {
    public:
      using framing_type = SeqPacketSocket;
      static constexpr bool uses_dynamic_buffers = true;
    };
  };
};

#endif
