#include <iostream>
#include <string>
#include <vector>
#include <boost/log/trivial.hpp>

#include "configuration.hpp"

namespace po = boost::program_options;

namespace stork {
  namespace flock {
    namespace flockd {
      Configuration::Configuration(int argc, const char **argv)
        : m_options("Available options"),
          m_stun_port(0),
          m_program_name(argc > 0 ? argv[0] : "<unknown>") {

        std::vector<std::string> listen_endpoints_raw;

        m_options.add_options()
          ("help,h", "Show this help message")
          ("listen", po::value< std::vector<std::string> >(&listen_endpoints_raw), "Listen at this endpoint")
          ("stun", po::value< std::uint16_t >(&m_stun_port), "Listen for STUN requests on this UDP/TCP port");

        po::store(po::parse_command_line(argc, argv, m_options), m_var_map);
        po::notify(m_var_map);

        if ( m_var_map.count("stun") == 0 )
          m_stun_port = 3478;

        for ( const auto &endpoint : listen_endpoints_raw ) {
          uri::Uri endpoint_uri(endpoint);
          if ( endpoint_uri.is_valid() )
            m_listen_endpoints.push_front(std::move(endpoint_uri));
          else
            BOOST_LOG_TRIVIAL(error) << endpoint << " is not a valid listening URI";
        }
      }

      bool Configuration::is_valid() const {
        if ( m_var_map.count("help") )
          return false;
        if ( m_listen_endpoints.size() == 0 )
          return false;

        return true;
      }

      void Configuration::print_usage() const {
        std::cerr << m_program_name << " - Stork flockd server" << std::endl;
        std::cerr << "Usage: " << m_program_name << " [options]" << std::endl << std::endl;

        std::cerr << m_options;
      }
    }
  }
}
