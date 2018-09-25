#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <boost/log/trivial.hpp>
#include <boost/filesystem/path.hpp>

#include "configuration.hpp"

namespace po = boost::program_options;

namespace stork {
  namespace flock {
    namespace flockd {
      Configuration::Configuration(int argc, const char **argv)
        : m_options("Available options"),
          m_stun_port(0), m_our_shard_index(-1),
          m_program_name(argc > 0 ? argv[0] : "<unknown>") {

        std::vector<std::string> listen_endpoints_raw;
        std::string appliance_endpoint_raw;
        boost::filesystem::path shards_file, cert_file;

        m_options.add_options()
          ("help,h", "Show this help message")
          ("listen", po::value< std::vector<std::string> >(&listen_endpoints_raw), "Listen for connections at this endpoint")
          ("appliance", po::value< std::string >(&appliance_endpoint_raw), "Listen for appliances at this endpoint")
          ("stun", po::value< std::uint16_t >(&m_stun_port), "Listen for STUN requests on this UDP/TCP port")
          ("shards", po::value< boost::filesystem::path >(&shards_file), "Shards file")
          ("certificate", po::value< boost::filesystem::path >(&cert_file), "Private key for flock");

        po::store(po::parse_command_line(argc, argv, m_options), m_var_map);
        po::notify(m_var_map);

        if ( m_var_map.count("stun") == 0 )
          m_stun_port = 3478;

        for ( const auto &endpoint : listen_endpoints_raw ) {
          uri::Uri endpoint_uri(endpoint);
          if ( endpoint_uri.is_valid() )
            m_listen_endpoints.emplace_front(std::move(endpoint_uri));
          else
            BOOST_LOG_TRIVIAL(error) << endpoint << " is not a valid listening URI";
        }

        if ( m_var_map.count("appliance") == 1 ) {
          uri::Uri endpoint_uri(appliance_endpoint_raw);
          if ( endpoint_uri.is_valid() && endpoint_uri.has_scheme("udp") &&
               endpoint_uri.has_port() ) {
            m_appliance_endpoint = std::move(endpoint_uri);
          } else
            BOOST_LOG_TRIVIAL(error) << appliance_endpoint_raw << " is not a valid appliance URI";
        }

        if ( m_var_map.count("certificate") == 1 ) {
          if ( boost::filesystem::is_directory(cert_file.parent_path()) ) {
            if ( boost::filesystem::is_regular_file(cert_file) ) {
              // Attempt to read in the certificate
              std::error_code ec;
              m_private_key.read_pem_from_file(cert_file, ec);
              if ( ec )
                BOOST_LOG_TRIVIAL(error) << "Could not open " << cert_file << ": " << ec;
            } else if ( !boost::filesystem::exists(cert_file) ) {
              // Generate certificate
              m_private_key.generate();
              m_private_key.write_pem_to_file(cert_file);
            } else
              BOOST_LOG_TRIVIAL(error) << cert_file << " exists but is not a regular file";
          } else
            BOOST_LOG_TRIVIAL(error) << cert_file.parent_path() << ": No such file or directory";
        }

        if ( m_var_map.count("shards") == 0 ) {
          m_our_shard_index = 0;
          m_shards.push_back(local_uri());
        } else {
          std::fstream shards_stream(shards_file.string(), std::fstream::in);
          std::string shard_uri_str;
          int cur_idx(0);

          while ( std::getline(shards_stream, shard_uri_str) ) {
            uri::Uri shard_uri(shard_uri_str);
            if ( !shard_uri.is_valid() ) {
              m_shards.clear();
              break;
            } else {
              if ( shard_uri == local_uri() ) {
                m_our_shard_index = cur_idx;
                m_shards.emplace_back(std::move(shard_uri));
              }
              cur_idx++;
            }
          }
        }
      }

      bool Configuration::is_valid() const {
        if ( m_var_map.count("help") )
          return false;
        if ( m_listen_endpoints.empty() || m_shards.empty() )
          return false;
        if ( !m_private_key.valid() )
          return false;

        return true;
      }

      void Configuration::print_usage() const {
        std::cerr << m_program_name << " - Stork flockd server" << std::endl;
        std::cerr << "Usage: " << m_program_name << " [options]" << std::endl << std::endl;

        std::cerr << m_options;
      }

      uri::Uri Configuration::local_uri() {
        char hostname[HOST_NAME_MAX];
        std::stringstream ep;
        ep << "udp://";

        if ( gethostname(hostname, HOST_NAME_MAX) < 0 ) {
          perror("gethostname");
          throw std::runtime_error("Could not get host name");
        }

        ep << hostname << ":" << m_appliance_endpoint.port_text();

        return uri::Uri(ep.str());
      }
    }
  }
}
