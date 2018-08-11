#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <boost/program_options/parsers.hpp>

#include "command.hpp"

namespace fs = boost::filesystem;
namespace po = boost::program_options;
namespace local = boost::asio::local;

namespace stork {
  namespace storkctl {
    Command::Command()
      : m_options("Allowed options") {

      m_options.add_options()("help", "produce help message");
    }

    void Command::parse_args(int argc, const char **argv) {
      std::vector<std::string> arg_vector;
      for ( int i = 0; i < argc; ++i )
        arg_vector.push_back(argv[i]);

      build_options_description();

      boost::program_options::store(boost::program_options::command_line_parser(arg_vector).
                                    options(m_options).positional(m_positional).run(), m_arguments);
      boost::program_options::notify(m_arguments);

      if (m_arguments.count("help")) {
        // TODO(travis) Output subcommand and description
        std::cerr << "storkctl " << std::endl;
        std::cerr << m_options << std::endl;
        std::exit(1);
      }
    }

    Command::~Command() {
    }

    std::ostream &Command::info() const {
      return std::cout;
    }

    ApiCommandMixin::~ApiCommandMixin() {
    }

    void ApiCommandMixin::parse_args(int argc, const char **argv) {
      Command::parse_args(argc, argv);

      if ( api_required() && parsed_args().count("stork-dir") != 1 )
        throw std::runtime_error("The --stork-dir argument is required");
      else if ( parsed_args().count("stork-dir") == 1 ) {
        m_stork_dir = parsed_args()["stork-dir"].as<std::string>();

        fs::path socketPath(m_stork_dir);
        socketPath /= "api.sock";

        fs::file_status sts(fs::status(socketPath));
        if ( sts.type() != fs::file_type::socket_file )
          throw std::runtime_error("The given stork directory socket is not a socket");
      }
    }

    void ApiCommandMixin::build_options_description() {
      m_options.add_options()("stork-dir", po::value<std::string>(), "Stork runtime directory");
    }

    local::stream_protocol::socket ApiCommandMixin::open_socket(boost::asio::io_service &svc) const {
      local::stream_protocol::socket s(svc);
      fs::path socketPath(m_stork_dir);
      socketPath /= "api.sock";
      s.connect(local::stream_protocol::endpoint(socketPath.string()));
      return s;
    }

    void ApiCommandMixin::send_command(local::stream_protocol::socket &socket,
                                       const proto::local::Command &cmd) {
      proto::FramedSender<std::uint16_t, local::stream_protocol::socket> sender(socket);

      sender.write<proto::local::Command>(cmd);
    }
  }
}
