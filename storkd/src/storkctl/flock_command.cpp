#include "flock_command.hpp"

namespace po = boost::program_options;

namespace stork {
  namespace storkctl {
    FlockCommand::FlockCommand(int argc, const char **argv) {
      parse_args(argc, argv);

      if ( !parsed_args().count("flock-uri") )
        throw std::runtime_error("The --flock-uri argument is required");

      m_flock_uri = parsed_args()["flock-uri"].as<std::string>();
    }

    FlockCommand::~FlockCommand() {
    }

    bool FlockCommand::api_required() const {
      return true;
    }

    void FlockCommand::build_options_description() {
      ApiCommandMixin::build_options_description();

      m_options.add_options()
        ("flock-uri", po::value<std::string>(), "The flock URI to operate on");
    }

    JoinFlockCommand::~JoinFlockCommand() {
    }

    int JoinFlockCommand::run() {
      proto::local::JoinFlockCommand cmd(m_flock_uri);

      proto::local::Response
        response(simple_api_command<proto::local::Response>(cmd));
      if ( response ) {
        info() << "Joining flock" << std::endl;;
        return 0;
      } else {
        info() << "Storkd returned an error while attempting to join the flock: " << response.status_string() << std::endl;
        return 1;
      }
    }
  }
}
