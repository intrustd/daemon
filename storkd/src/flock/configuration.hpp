#ifndef __stork_flockd_configuration_HPP__
#define __stork_flockd_configuration_HPP__

#include <boost/program_options.hpp>
#include <boost/asio.hpp>
#include <list>

#include "../uri.hpp"
#include "../crypto/certificate.hpp"

namespace stork {
  namespace flock {
    namespace flockd {
      class Configuration {
      public:
        Configuration(int argc, const char **argv);

        bool is_valid() const;
        void print_usage() const;

        inline const std::list<uri::Uri> &listen_endpoints() const { return m_listen_endpoints; }
        inline const uri::Uri &appliance_endpoint() const { return m_appliance_endpoint; }
        inline std::uint16_t stun_port() const { return m_stun_port; }

        inline int our_shard_index() const { return m_our_shard_index; }
        inline const std::list<uri::Uri> shards() const { return m_shards; }

        inline const crypto::Key &private_key() const { return m_private_key; }

      private:
        uri::Uri local_uri();

        boost::program_options::variables_map m_var_map;
        boost::program_options::options_description m_options;

        std::list<uri::Uri> m_listen_endpoints;
        uri::Uri m_appliance_endpoint;
        std::uint16_t m_stun_port;

        int m_our_shard_index;
        std::list<uri::Uri> m_shards;

        crypto::Key m_private_key;

        const char *m_program_name;
      };
    }
  }
}

#endif
