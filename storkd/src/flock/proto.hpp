#ifndef __stork_flock_proto_HPP__
#define __stork_flock_proto_HPP__

#include <list>
#include <boost/property_tree/ptree.hpp>
#include <boost/chrono.hpp>

#include "../proto.hpp"
#include "../backend.hpp"
#include "../application/application.hpp"

namespace stork {
  namespace proto {
    namespace flock {
      typedef std::uint32_t ProtoVersion;

      class ICommandDispatch;

      class Command {
      public:
        virtual ~Command();

        typedef uint32_t CommandName;
        inline CommandName name() const { return m_name; }

        static std::unique_ptr<Command> read(ProtoParser &parser);
        void write(ProtoBuilder &parser) const;

        virtual void dispatch(ICommandDispatch &d) const =0;

        struct Names {
          static const CommandName ping            = 0x00000000;
          static const CommandName register_device = 0x00000001;
          static const CommandName login_to_device = 0x00000002;
          static const CommandName dial_session    = 0x00000003;

          // Commands sent to devices
          static const CommandName start_login     = 0xFFFFFFFE;
        };

      protected:
        inline Command(CommandName name)
          : m_name(name) {
        }

        virtual void write_data(ProtoBuilder &b) const =0;

      private:
        CommandName m_name;
      };

      class RegisterDeviceCommand : public Command {
      public:
        virtual ~RegisterDeviceCommand();

        RegisterDeviceCommand(ProtoParser &parser);
        RegisterDeviceCommand(ProtoVersion v, const std::string &name);

        inline const std::string &name() const { return m_name; }
        inline ProtoVersion proto_version() const { return m_version; }

        virtual void dispatch(ICommandDispatch &d) const;

      protected:
        virtual void write_data(ProtoBuilder &b) const;

      private:
        ProtoVersion m_version;
        std::string m_name;
      };


      class LoginToDeviceCommand : public Command {
      public:
        virtual ~LoginToDeviceCommand();

        LoginToDeviceCommand(ProtoParser &parser);
        LoginToDeviceCommand(ProtoVersion v, const std::string &name);

        inline const std::string &name() const { return m_name; }
        inline ProtoVersion proto_version() const { return m_version; }

        inline void set_credentials(backend::LoginCredentials &&creds) {
          m_credentials = std::make_unique<backend::LoginCredentials>(std::move(creds));
        }
        inline bool has_credentials() const { return (bool) m_credentials; }
        inline const backend::LoginCredentials &credentials() const { return *m_credentials; }

        virtual void dispatch(ICommandDispatch &d) const;

      protected:
        virtual void write_data(ProtoBuilder &b) const;

      private:
        ProtoVersion m_version;
        std::string m_name;
        std::unique_ptr<backend::LoginCredentials> m_credentials;
      };

      class StartLoginCommand : public Command {
      public:
        virtual ~StartLoginCommand();

        StartLoginCommand(ProtoParser &parser);
        StartLoginCommand();

        virtual void dispatch(ICommandDispatch &d) const;

      protected:
        virtual void write_data(ProtoBuilder &b) const;
      };

      class PingCommand : public Command {
      public:
        virtual ~PingCommand();

        inline PingCommand(ProtoParser &parser) : Command(Command::Names::ping) {};
        inline PingCommand() : Command(Command::Names::ping) {};

        virtual void dispatch(ICommandDispatch &d) const;

      protected:
        virtual void write_data(ProtoBuilder &b) const;
      };

      class DialSessionCommand : public Command {
      public:
        virtual ~DialSessionCommand();

        enum signal_type : std::uint8_t {
          dial_done = 0x0,
            session_description = 0x1,
            ice_candidate = 0x2
        };

        inline DialSessionCommand(const std::string &token, signal_type type, const std::string &data)
          : Command(Command::Names::dial_session), m_type(type), m_token(token), m_data(data) {
        }
        //        DialSessionCommand(DialSessionCommand &&c) =default;
        DialSessionCommand(ProtoParser &p);

        virtual void dispatch(ICommandDispatch &d) const;

        inline signal_type type() const { return m_type; }
        inline const std::string &token() const { return m_token; }
        inline const std::string &data() const { return m_data; }

        inline bool needs_response() const { return m_type == dial_done; }
        inline bool valid() const {
          return m_type == dial_done ||
            m_type == session_description ||
            m_type == ice_candidate;
        }

      protected:
        virtual void write_data(ProtoBuilder &b) const;

      private:
        signal_type m_type;
        std::string m_token, m_data;
      };

      class ICommandDispatch {
      public:
        virtual ~ICommandDispatch();

        virtual void ping(const PingCommand &cmd) =0;

        virtual void register_device(const RegisterDeviceCommand &cmd) =0;
        virtual void login_to_device(const LoginToDeviceCommand &cmd) =0;

        virtual void start_login(const StartLoginCommand &cmd) =0;

        virtual void dial_session(const DialSessionCommand &cmd) =0;
      };

      // Responses

      class Response {
      public:
        typedef uint16_t ResponseCode;

        Response(ProtoParser &p);
        inline Response(ResponseCode c)
          : m_status(c) {
        }
        Response(const Response &r) =default;
        Response(Response &&r) =default;

        virtual ~Response();

        struct Codes {
          static const ResponseCode success = 0;
          static const ResponseCode unknown_error = 1;
          static const ResponseCode device_already_registered = 2;
          static const ResponseCode no_such_device = 3;
          static const ResponseCode personas_not_listed = 4;
          static const ResponseCode no_more_entries = 5;
          static const ResponseCode device_malfunction = 6;
          static const ResponseCode invalid_credentials = 7;
          static const ResponseCode invalid_state = 8;
          static const ResponseCode invalid_dial = 9;
          static const ResponseCode invalid_request = 10;
        };

        inline bool is_error() const { return m_status != Codes::success; }
        inline ResponseCode status() const { return m_status; }
        const char *status_string() const;

        inline operator bool() const { return !is_error(); }

        void write(ProtoBuilder &builder) const;

      protected:
        virtual void write_data(ProtoBuilder &builder) const;

      private:
        ResponseCode m_status;
      };

      class RegisterDeviceResponse : public Response {
      public:
        virtual ~RegisterDeviceResponse();

        RegisterDeviceResponse(ProtoParser &p);
        inline RegisterDeviceResponse(ProtoVersion v, const std::string &login_token,
                                      boost::chrono::seconds login_token_ttl)
          : Response(Response::Codes::success), m_proto_version(v),
            m_login_token(login_token), m_login_token_ttl(login_token_ttl) {
        }

        inline ProtoVersion proto_version() const { return m_proto_version; }
        inline const std::string &login_token() const { return m_login_token; }
        inline boost::chrono::seconds login_token_ttl() const { return m_login_token_ttl; }

      protected:
        virtual void write_data(ProtoBuilder &builder) const;

      private:
        ProtoVersion m_proto_version;
        std::string m_login_token;
        boost::chrono::seconds m_login_token_ttl;
      };

      class LoginToDeviceResponse : public Response {
      public:
        typedef std::list< std::pair<std::string, std::string> > properties;
        virtual ~LoginToDeviceResponse();

        LoginToDeviceResponse(ProtoParser &p);

        inline LoginToDeviceResponse(properties &&profile_properties)
          : Response(Response::Codes::success),
            m_properties(std::move(profile_properties)) {
        }
        inline LoginToDeviceResponse(properties &profile_properties)
          : Response(Response::Codes::success),
            m_properties(profile_properties) {
        }

        LoginToDeviceResponse(LoginToDeviceResponse &&r) =default;

        static LoginToDeviceResponse no_more_entries() {
          return LoginToDeviceResponse(Response::Codes::no_more_entries);
        }
        static LoginToDeviceResponse personas_not_listed() {
          return LoginToDeviceResponse(Response::Codes::personas_not_listed);
        }
        static LoginToDeviceResponse device_malfunction() {
          return LoginToDeviceResponse(Response::Codes::device_malfunction);
        }
        static LoginToDeviceResponse unknown_error() {
          return LoginToDeviceResponse(Response::Codes::unknown_error);
        }
        static LoginToDeviceResponse invalid_credentials() {
          return LoginToDeviceResponse(Response::Codes::invalid_credentials);
        }

        inline const properties &profile_properties() const { return m_properties; }

      protected:
        virtual void write_data(ProtoBuilder &builder) const;

      private:
        inline LoginToDeviceResponse(ResponseCode c)
          : Response(c) {
        }

        properties m_properties;
      };

      class DialResponse : public Response {
      public:
        DialResponse(const std::string &sdp, const std::list<std::string> &cs);
        DialResponse(ProtoParser &p);
        virtual ~DialResponse();

      protected:
        virtual void write_data(ProtoBuilder &builder) const;

      private:
        std::string m_sdp;
        std::list<std::string> m_candidates;
      };
    }
  }
}

#endif
