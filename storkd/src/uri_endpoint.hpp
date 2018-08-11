#ifndef __stork_uri_endpoint_HPP__
#define __stork_uri_endpoint_HPP__

#include "uri.hpp"
#include "websocket.hpp"

namespace stork {
  namespace uri {
    template< template<typename> typename RegisterEndpoint, typename... Args >
    uri::ErrorCode run_with_endpoint(boost::asio::io_service &service,
                                     const uri::Uri &endpoint,
                                     Args... args) {
      if ( endpoint.has_scheme("tcp") || endpoint.has_scheme("ws") ) {
        if ( !endpoint.has_port() )
          return uri::missing_port;
        else {
          boost::asio::ip::tcp::resolver r(service);
          boost::system::error_code ec;
          int found_endpoints(0);

          auto results(r.resolve(endpoint.host(), endpoint.port_text(),
                                 boost::asio::ip::tcp::resolver::passive |
                                 boost::asio::ip::tcp::resolver::address_configured |
                                 boost::asio::ip::tcp::resolver::numeric_service,
                                 ec));

          if ( endpoint.has_scheme("tcp") ) {
            RegisterEndpoint<boost::asio::ip::tcp> register_this(args...);
            for ( const auto &endpoint: results ) {
              if ( ec ) {
                BOOST_LOG_TRIVIAL(error) << "System error while resolving url: " << ec;
                return uri::invalid_source;
              }

              register_this(endpoint.endpoint());
              found_endpoints++;
            }
          } else if ( endpoint.has_scheme("ws") ) {
            RegisterEndpoint< stork::websocket<boost::asio::ip::tcp> > register_this(args...);
            for ( const auto &endpoint: results ) {
              if ( ec ) {
                BOOST_LOG_TRIVIAL(error) << "System error while resolving url: " << ec;
                return uri::invalid_source;
              }

              register_this(endpoint.endpoint());
              found_endpoints++;
            }
          }

          if ( found_endpoints == 0 )
            return uri::not_found;

          return uri::success;
        }
      } else
        return uri::unknown_scheme;
    }
  }
}

#endif
