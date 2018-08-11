#ifndef __stork_flockd_configuration_HPP__
#define __stork_flockd_configuration_HPP__

#include <boost/program_options.hpp>
#include <list>

#include "../uri.hpp"

namespace stork {
  namespace flock {
    namespace flockd {
      class Configuration {
      public:
        Configuration(int argc, const char **argv);

        bool is_valid() const;
        void print_usage() const;

        inline const std::list<uri::Uri> &listen_endpoints() const { return m_listen_endpoints; }
        inline std::uint16_t stun_port() const { return m_stun_port; }

      private:
        boost::program_options::variables_map m_var_map;
        boost::program_options::options_description m_options;

        std::list<uri::Uri> m_listen_endpoints;
        std::uint16_t m_stun_port;

        const char *m_program_name;
      };
    }
  }
}

#endif
