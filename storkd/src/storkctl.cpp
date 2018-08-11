#include <iostream>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/filesystem.hpp>

#include "storkctl/command.hpp"
#include "storkctl/persona_command.hpp"
#include "storkctl/application_command.hpp"
#include "storkctl/flock_command.hpp"

namespace fs = boost::filesystem;
namespace local = boost::asio::local;
namespace storkctl = stork::storkctl;

storkctl::Command::Factory commands[] = {
  storkctl::Command::Factory("new-persona", &storkctl::NewPersonaCommand::build),
  storkctl::Command::Factory("install-application", &storkctl::InstallApplicationCommand::build),

  storkctl::Command::Factory("register-application", &storkctl::RegisterApplicationCommand::build),
  storkctl::Command::Factory("list-applications", &storkctl::ListApplicationsCommand::build),

  storkctl::Command::Factory("join-flock", &storkctl::JoinFlockCommand::build)
};
int command_count = sizeof(commands)/sizeof(commands[0]);

void usage() {

  std::cerr << "storkctl - Control a running storkd server" << std::endl;
  std::cerr << "Usage: storkctl [storkdir] [subcommand] [options]" << std::endl;
  std::cerr << std::endl;
  std::cerr << "Where subcommand is one of:" << std::endl;
  for ( int i = 0; i < command_count; ++i )
    std::cerr << "   - " << commands[i].command_name() << std::endl;
}

int main(int argc, const char **argv) {
  if ( argc < 2 ) {
    usage();
    return 1;
  } else {
    std::string subcommand(argv[1]);

    for ( int i = 0; i < command_count; ++i ) {
      if ( commands[i].command_name() == subcommand ) {
        std::unique_ptr<stork::storkctl::Command> command(commands[i].build(argc - 2, argv + 2));
        return command->run();
      }
    }

    std::cerr << "Unknown subcommand " << subcommand << std::endl;
    return 1;
  }
}
