#include <iostream>

#include "../local_proto.hpp"
#include "../persona/profile.hpp"
#include "persona_command.hpp"

namespace po = boost::program_options;
namespace local = boost::asio::local;

namespace stork {
  namespace storkctl {
    NewPersonaCommand::NewPersonaCommand(int argc, const char **argv) {
      parse_args(argc, argv);

      if ( !parsed_args().count("name") )
        throw std::runtime_error("The --name argument is required");
    }

    NewPersonaCommand::~NewPersonaCommand() {}

    bool NewPersonaCommand::api_required() const { return true; }

    int NewPersonaCommand::run() {
      info() << "Creating persona with name " << m_full_name << std::endl;


      stork::proto::local::NewPersonaCommand cmd;
      cmd.profile().full_name(m_full_name);

      if ( parsed_args().count("email") )
        cmd.profile().email(m_email);
      //      NewPersonaResponse response;

      proto::local::NewPersonaResponse
        response(simple_api_command<proto::local::NewPersonaResponse>(cmd));

      if ( response ) {
        info() << "New persona created with id " << response.id().id() << std::endl;
        return 0;
      } else {
        info() << "There was an error while creating the persona: " << response.status_string() << std::endl;
        return 1;
      }
    }

    void NewPersonaCommand::build_options_description() {
      ApiCommandMixin::build_options_description();

      m_options.add_options()
        ("name", po::value<std::string>(&m_full_name), "The name of the persona")
        ("email", po::value<std::string>(&m_email), "Optional email for persona");
    }
  }
}
