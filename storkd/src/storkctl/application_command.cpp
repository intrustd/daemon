#include "application_command.hpp"

namespace po = boost::program_options;

namespace stork {
  namespace storkctl {
    RegisterApplicationCommand::RegisterApplicationCommand(int argc, const char **argv) {
      parse_args(argc, argv);

      if ( !parsed_args().count("manifest") )
        throw std::runtime_error("The --manifest argument is required");
    }

    RegisterApplicationCommand::~RegisterApplicationCommand() {}

    bool RegisterApplicationCommand::api_required() const { return true; }

    int RegisterApplicationCommand::run() {
      info() << "Creating application with manifest " << m_manifest_url << std::endl;

      proto::local::RegisterApplicationCommand cmd(m_manifest_url);
      proto::local::Response
        response(simple_api_command<proto::local::Response>(cmd));

      if ( response ) {
        info() << "Registered successfully" << std::endl;
        return 0;
      } else {
        info () << "Error registering application: " << response.status_string() << std::endl;
        return 0;
      }
    }

    void RegisterApplicationCommand::build_options_description() {
      ApiCommandMixin::build_options_description();

      m_options.add_options()
        ("manifest", po::value<std::string>(&m_manifest_url), "The manifest URL for the application");
    }

    ListApplicationsCommand::ListApplicationsCommand(int argc, const char **argv) {
      parse_args(argc, argv);
    }

    ListApplicationsCommand::~ListApplicationsCommand() {
    }

    int ListApplicationsCommand::run() {
      boost::asio::io_service svc;
      boost::asio::local::stream_protocol::socket socket(open_socket(svc));

      proto::local::ListApplicationsCommand cmd;
      send_command(socket, cmd);

      for ( auto r(read_response<proto::local::ApplicationResultResponse>(socket));
            !r.is_end();
            r = read_response<proto::local::ApplicationResultResponse>(socket) )
        info() << "  - [" << r.app_id().canonical_url() << "] " << r.name() << std::endl;

      return 0;
    }

    bool ListApplicationsCommand::api_required() const {
      return true;
    }

    void ListApplicationsCommand::build_options_description() {
      ApiCommandMixin::build_options_description();
    }

    InstallApplicationCommand::InstallApplicationCommand(int argc, const char **argv) {
      this->ApiCommandMixin::parse_args(argc, argv);

      if ( parsed_args().count("app") == 0 )
        throw std::runtime_error("The --app option is required");
      if ( parsed_args().count("persona") == 0 )
        throw std::runtime_error("The --persona option is required");

      uri::Uri app_uri(parsed_args()["app"].as<std::string>());

      if ( app_uri.is_valid() ) {
        bool successful(false);
        m_app_id = application::ApplicationIdentifier::from_canonical_url(app_uri, successful);
        if ( !successful )
          throw std::runtime_error("Invalid application id");
      } else
        throw std::runtime_error("Expected a valid application URI");

      m_persona_id = parsed_args()["persona"].as<std::string>();
    }

    InstallApplicationCommand::~InstallApplicationCommand() {
    }


    bool InstallApplicationCommand::api_required() const { return true; }

    int InstallApplicationCommand::run() {
      proto::local::InstallApplicationCommand cmd(m_persona_id, m_app_id);
      auto r(simple_api_command<proto::local::Response>(cmd));

      if ( r.status() == proto::local::Response::Codes::success ) {
        std::cout << "Installation successful";
      } else {
        std::cout << "Error installing application: " << r.status_string();
      }
      return 0;
    }

    void InstallApplicationCommand::build_options_description() {
      ApiCommandMixin::build_options_description();

      m_options.add_options()
        ("app", po::value<std::string>(), "The app url to install")
        ("persona", po::value<std::string>(), "The persona ID to install under");
    }
  }
}
