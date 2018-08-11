#include <boost/log/trivial.hpp>
#include <list>

#include "proto.hpp"

namespace stork {
  namespace proto {
    namespace flock {
      ICommandDispatch::~ICommandDispatch() {
      }

      Command::~Command() {
      }

      std::unique_ptr<Command> Command::read(ProtoParser &parser) {
        CommandName nm;

        parser.parse("command name", nm);
        switch ( nm ) {
        case Names::ping:
          return std::make_unique<PingCommand>(parser);
        case Names::register_device:
          return std::make_unique<RegisterDeviceCommand>(parser);
        case Names::login_to_device:
          return std::make_unique<LoginToDeviceCommand>(parser);
        case Names::start_login:
          return std::make_unique<StartLoginCommand>(parser);
        case Names::dial_session:
          return std::make_unique<DialSessionCommand>(parser);
        default:
          return std::unique_ptr<Command>();
        }
      }

      void Command::write(ProtoBuilder &b) const {
        b.inter(m_name);
        write_data(b);
      }

      RegisterDeviceCommand::RegisterDeviceCommand(ProtoParser &parser)
        : Command(Names::register_device) {
        parser.parse("protocol version", m_version)
          .parseVarLenString("appliance name", m_name);
      }

      RegisterDeviceCommand::RegisterDeviceCommand(ProtoVersion v, const std::string &nm)
        : Command(Names::register_device),
          m_version(v), m_name(nm) {
      }

      RegisterDeviceCommand::~RegisterDeviceCommand() {
      }

      void RegisterDeviceCommand::dispatch(ICommandDispatch &d) const {
        d.register_device(*this);
      }

      void RegisterDeviceCommand::write_data(ProtoBuilder &b) const {
        b.inter(m_version).interVarLenString(m_name);
      }

      LoginToDeviceCommand::LoginToDeviceCommand(ProtoParser &parser)
        : Command(Names::login_to_device) {
        parser.parse("protocol version", m_version)
          .parseVarLenString("appliance name", m_name);

        try {
          backend::LoginCredentials creds;
          parser.parseObject("credentials", creds);
          set_credentials(std::move(creds));
        } catch (ProtoParseException &e) {
        }
      }

      LoginToDeviceCommand::LoginToDeviceCommand(ProtoVersion v, const std::string &nm)
        : Command(Names::login_to_device),
          m_version(v), m_name(nm) {
      }

      LoginToDeviceCommand::~LoginToDeviceCommand() {
      }

      void LoginToDeviceCommand::dispatch(ICommandDispatch &d) const {
        d.login_to_device(*this);
      }

      void LoginToDeviceCommand::write_data(ProtoBuilder &b) const {
        b.inter(m_version).interVarLenString(m_name);
        if ( has_credentials() )
          b.interObject(credentials());
      }

      StartLoginCommand::StartLoginCommand()
        : Command(Command::Names::start_login) {
      }

      StartLoginCommand::StartLoginCommand(ProtoParser &p)
        : Command(Command::Names::start_login) {
      }

      StartLoginCommand::~StartLoginCommand() {
      }

      void StartLoginCommand::dispatch(ICommandDispatch &d) const {
        d.start_login(*this);
      }

      void StartLoginCommand::write_data(ProtoBuilder &b) const {
      }

      DialSessionCommand::~DialSessionCommand() {
      }

      DialSessionCommand::DialSessionCommand(ProtoParser &p)
        : Command(Command::Names::dial_session) {
        p.parse("type", m_type)
          .parseVarLenString("token", m_token)
          .parseVarLenString("data", m_data);
      }

      void DialSessionCommand::dispatch(ICommandDispatch &d) const {
        d.dial_session(*this);
      }

      void DialSessionCommand::write_data(ProtoBuilder &b) const {
        b.inter(m_type).interVarLenString(m_token)
          .interVarLenString(m_data);
      }

      PingCommand::~PingCommand() {
      }

      void PingCommand::dispatch(ICommandDispatch &d) const {
        d.ping(*this);
      }

      void PingCommand::write_data(ProtoBuilder &b) const {
      }

      //Responses

      Response::Response(ProtoParser &p) {
        p.parse("status code", m_status);
      }

      Response::~Response() {
      }

      const char *Response::status_string() const {
        switch (status()) {
        case Codes::success:
          return "Success";
        case Codes::device_already_registered:
          return "Device already registered";
        case Codes::no_such_device:
          return "No such device";
        case Codes::personas_not_listed:
          return "Personas not listed";
        case Codes::no_more_entries:
          return "No more entries";
        case Codes::device_malfunction:
          return "Remote device malfunction";
        case Codes::invalid_credentials:
          return "Invalid credentials";
        case Codes::invalid_state:
          return "Invalid state";
        case Codes::unknown_error:
        default:
          return "Unknown error";
        };
      }

      void Response::write(ProtoBuilder &builder) const {
        builder.inter(m_status);
        write_data(builder);
      }

      void Response::write_data(ProtoBuilder &builder) const {
      }

      RegisterDeviceResponse::RegisterDeviceResponse(ProtoParser &p)
        : Response(p) {

        if ( status() == Codes::success ) {
          unsigned long login_ttl;
          p.parse("protocol version", m_proto_version)
            .parseVarLenString("login token", m_login_token)
            .parse("login ttl", login_ttl);
          m_login_token_ttl = boost::chrono::seconds(login_ttl);
        } else {
          m_proto_version = 0;
          m_login_token_ttl = boost::chrono::seconds(0);
        }
      }

      RegisterDeviceResponse::~RegisterDeviceResponse() {
      }

      void RegisterDeviceResponse::write_data(ProtoBuilder &builder) const {
        unsigned long login_ttl = m_login_token_ttl.count();
        builder.inter(m_proto_version)
          .interVarLenString(m_login_token)
          .inter(login_ttl);
      }

      LoginToDeviceResponse::~LoginToDeviceResponse() {
      }

      LoginToDeviceResponse::LoginToDeviceResponse(ProtoParser &p)
        : Response(p) {
        p.parseList("properties", std::back_insert_iterator< properties >(m_properties), [&p] () {
            std::string k, v;
            p.parseVarLenString("key", k).parseVarLenString("value", v);
            return std::make_pair<std::string, std::string>
              (std::move(k), std::move(v));
          });
      }

      void LoginToDeviceResponse::write_data(ProtoBuilder &builder) const {
        builder.interList(m_properties, [&builder] (const std::pair<std::string, std::string> &prop) {
            builder.interVarLenString(prop.first)
              .interVarLenString(prop.second);
          });
      }

      // DialResponse
      DialResponse::DialResponse(const std::string &sdp, const std::list<std::string> &cs)
        : Response(Response::Codes::success), m_sdp(sdp), m_candidates(cs) {
      }

      DialResponse::DialResponse(ProtoParser &p)
        : Response(p) {

        if ( status() == Response::Codes::success ) {
          p.parseVarLenString("answer", m_sdp)
            .parseList("candidates", std::back_insert_iterator< std::list<std::string> >(m_candidates),
                       [&p] () {
                         std::string c;
                         p.parseVarLenString("candidate", c);
                         return c;
                       });
        }
      }

      DialResponse::~DialResponse() {
      }

      void DialResponse::write_data(ProtoBuilder &builder) const {
        if ( status() == Response::Codes::success ) {
          builder.interVarLenString(m_sdp)
            .interList(m_candidates, [&builder] ( const std::string &c ) {
                builder.interVarLenString(c);
              });
        }
      }
    }
  }
}
