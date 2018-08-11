#ifndef __stork_local_api_HPP__
#define __stork_local_api_HPP__
#include <boost/asio.hpp>
#include <boost/asio/local/stream_protocol.hpp>

namespace stork {
  namespace appliance {
    class Appliance;
    class LocalApi {
    public:
      LocalApi(Appliance &appliance, boost::asio::io_service &service);
      ~LocalApi();

      inline Appliance &appliance() { return m_appliance; }

    private:
      void start();
      void accept();

      Appliance &m_appliance;
      boost::asio::io_service &m_service;
      boost::asio::local::stream_protocol::acceptor m_acceptor;
    };
  }
}

#endif
