#include "local_proto.hpp"

namespace stork {
  namespace proto {
    namespace local {
      ICommandDispatch::~ICommandDispatch() {
      }

      Command::~Command() { }

      void Command::write(proto::ProtoBuilder &b) const {
        b.inter(m_name);
        write_data(b);
      }

      std::unique_ptr<Command> Command::read(proto::ProtoParser &p) {
        CommandName nm;
        p.parse("command name", nm);

        switch ( nm ) {
        case Names::NewPersona:
          return std::make_unique<NewPersonaCommand>(p);
        case Names::InstallApplication:
          return std::make_unique<InstallApplicationCommand>(p);
        case Names::RegisterApplication:
          return std::make_unique<RegisterApplicationCommand>(p);
        case Names::ListApplications:
          return std::make_unique<ListApplicationsCommand>(p);
        case Names::JoinFlock:
          return std::make_unique<JoinFlockCommand>(p);
        default:
          return std::unique_ptr<Command>();
        }
      }

      NewPersonaCommand::NewPersonaCommand(ProtoParser &p)
        : Command(Names::NewPersona),
          m_profile(p) {
      }

      NewPersonaCommand::~NewPersonaCommand() {}

      void NewPersonaCommand::dispatch(ICommandDispatch &dispatch) const {
        dispatch.new_persona(*this);
      }

      void NewPersonaCommand::write_data(ProtoBuilder &builder) const {
        builder.interObject(m_profile);
      }

      InstallApplicationCommand::InstallApplicationCommand(ProtoParser &p)
        : Command(Names::InstallApplication) {

        p.parseObject("persona id", m_persona_id)
          .parseObject("app id", m_app_id);
      }

      InstallApplicationCommand::~InstallApplicationCommand() {}

      void InstallApplicationCommand::dispatch(ICommandDispatch &dispatch) const {
        dispatch.install_application(*this);
      }

      void InstallApplicationCommand::write_data(ProtoBuilder &builder) const {
        builder.interObject(m_persona_id)
          .interObject(m_app_id);
      }

      RegisterApplicationCommand::RegisterApplicationCommand(ProtoParser &parser)
        : Command(Names::RegisterApplication) {
        parser.parseVarLenString("application manifest url", m_application_manifest_url);
      }

      RegisterApplicationCommand::~RegisterApplicationCommand() {}

      void RegisterApplicationCommand::dispatch(ICommandDispatch &dispatch) const {
        dispatch.register_app(*this);
      }

      void RegisterApplicationCommand::write_data(ProtoBuilder &builder) const {
        builder.interVarLenString(m_application_manifest_url);
      }

      ListApplicationsCommand::ListApplicationsCommand(ProtoParser &parser)
        : Command(Names::ListApplications) {
      }

      ListApplicationsCommand::~ListApplicationsCommand() {
      }

      void ListApplicationsCommand::dispatch(ICommandDispatch &d) const {
        d.list_applications(*this);
      }

      void ListApplicationsCommand::write_data(ProtoBuilder &builder) const {
      }

      JoinFlockCommand::JoinFlockCommand(ProtoParser &parser)
        : Command(Names::JoinFlock) {
        std::string flock_uri;
        parser.parseVarLenString("flock uri", flock_uri);

        m_flock_uri = flock_uri;
      }

      JoinFlockCommand::~JoinFlockCommand() {
      }

      void JoinFlockCommand::dispatch(ICommandDispatch &d) const {
        d.join_flock(*this);
      }

      void JoinFlockCommand::write_data(ProtoBuilder &b) const {
        b.interVarLenString(m_flock_uri.raw());
      }

      Response::~Response() {
      }

      Response::Response(ProtoParser &p) {
        p.parse("status code", m_status);
      }

      const char *Response::status_string() const {
        switch ( m_status ) {
        case Codes::success:
          return "Success";
        case Codes::unimplemented:
          return "Unimplemented";
        case Codes::invalid_uri:
          return "Invalid URI";
        case Codes::app_data:
          return "App data";
        case Codes::unavailable:
          return "Unavailable";
        case Codes::manifest_not_found:
          return "Manifest not found";
        case Codes::unknown_uri_scheme:
          return "Unknown URI scheme";
        case Codes::invalid_manifest:
          return "Invalid manifest";
        case Codes::no_more_data:
          return "End of list";
        default:
        case Codes::unknown_error:
          return "Unknown error";
        }
      }

      void Response::write(ProtoBuilder &b) const {
        b.inter<ResponseCode>(m_status);
        write_data(b);
      }

      void Response::write_data(ProtoBuilder &b) const {
      }

      NewPersonaResponse::NewPersonaResponse(ProtoParser &parser)
        : Response(parser) {

        if ( *this ) {
          parser.parseObject("persona id", m_id);
        }
      }

      void NewPersonaResponse::write_data(ProtoBuilder &builder) const {
        builder.interObject(m_id);
      }

      ApplicationResultResponse::ApplicationResultResponse(ProtoParser &parser)
        : Response(parser) {
        if ( !is_end() ) {
          parser.parseObject("application id", m_app_id)
            .parseVarLenString("application name", m_name);
        }
      }

      void ApplicationResultResponse::write_data(ProtoBuilder &builder) const {
        if ( !is_end() ) {
          builder.interObject(m_app_id).interVarLenString(m_name);
        }
      }
    }
  }
}
