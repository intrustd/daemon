#ifndef __stork_local_proto_HPP__
#define __stork_local_proto_HPP__

#include <cstdint>
#include <memory>

#include "proto.hpp"
#include "persona/profile.hpp"
#include "backend.hpp"

namespace stork {
  namespace proto {
    namespace local {
      class ICommandDispatch;

      class Command {
      public:
        virtual ~Command();

        typedef uint32_t CommandName;
        inline CommandName name() const { return m_name; }

        static std::unique_ptr<Command> read(ProtoParser &parser);
        void write(ProtoBuilder &parser) const;

        virtual void dispatch(ICommandDispatch &dispatch) const =0;

        struct Names {
          static const CommandName NewPersona = 1;
          static const CommandName InstallApplication = 2;

          // Redownloads bundle and triggers rebuild
          static const CommandName UpdateApplication = 3;

          static const CommandName StartApplication = 4;
          static const CommandName StopApplication = 5;

          static const CommandName RegisterApplication = 100;
          static const CommandName ListApplications = 101;

          static const CommandName JoinFlock = 200;
        };

      protected:
        inline Command(CommandName name)
          : m_name(name) {
        }
        virtual void write_data(ProtoBuilder &parser) const =0;

      private:
        CommandName m_name;
      };

      class NewPersonaCommand : public Command {
      public:
        virtual ~NewPersonaCommand();

        inline NewPersonaCommand(stork::persona::Profile &profile)
          : Command(Command::Names::NewPersona),
            m_profile(profile) {
        };
        inline NewPersonaCommand()
          : Command(Command::Names::NewPersona) {
        }

        NewPersonaCommand(ProtoParser &parser);

        virtual void dispatch(ICommandDispatch &dispatch) const;

        stork::persona::Profile &profile() { return m_profile; }
        const stork::persona::Profile &profile() const { return m_profile; }

      protected:
        virtual void write_data(ProtoBuilder &builder) const;

      private:
        stork::persona::Profile m_profile;
      };

      class InstallApplicationCommand : public Command {
      public:
        virtual ~InstallApplicationCommand();

        inline InstallApplicationCommand(const backend::PersonaId &id,
                                         const application::ApplicationIdentifier &app_id)
          : Command(Names::InstallApplication),
            m_persona_id(id),
            m_app_id(app_id) {
        }
        InstallApplicationCommand(ProtoParser &parser);

        virtual void dispatch(ICommandDispatch &dispatch) const;

        inline const backend::PersonaId &persona_id() const { return m_persona_id; }
        inline const application::ApplicationIdentifier &app_id() const { return m_app_id; }

      protected:
        virtual void write_data(ProtoBuilder &builder) const;
      private:
        backend::PersonaId m_persona_id;
        application::ApplicationIdentifier m_app_id;
      };

      class RegisterApplicationCommand : public Command {
      public:
        virtual ~RegisterApplicationCommand();

        inline RegisterApplicationCommand(const std::string &application_manifest_url)
          : Command(Names::RegisterApplication),
            m_application_manifest_url(application_manifest_url) {
        }
        RegisterApplicationCommand(ProtoParser &parser);

        virtual void dispatch(ICommandDispatch &dispatch) const;

        inline const std::string &application_manifest_url() const { return m_application_manifest_url; }

      protected:
        virtual void write_data(ProtoBuilder &builder) const;
      private:
        std::string m_application_manifest_url;
      };

      class ListApplicationsCommand : public Command {
      public:
        virtual ~ListApplicationsCommand();

        inline ListApplicationsCommand()
          : Command(Command::Names::ListApplications) {};
        ListApplicationsCommand(ProtoParser &parser);

        virtual void dispatch(ICommandDispatch &dispatch) const;

      protected:
        virtual void write_data(ProtoBuilder &builder) const;
      };

      class JoinFlockCommand : public Command {
      public:
        virtual ~JoinFlockCommand();

        inline JoinFlockCommand(const uri::Uri &uri)
          : Command(Command::Names::JoinFlock),
            m_flock_uri(uri) {
        }
        inline JoinFlockCommand(ProtoParser &parser);

        virtual void dispatch(ICommandDispatch &dispatch) const;

        const uri::Uri &flock_uri() const { return m_flock_uri; }

      protected:
        virtual void write_data(ProtoBuilder &builder) const;

      private:
        uri::Uri m_flock_uri;
      };

      class ICommandDispatch {
      public:
        virtual ~ICommandDispatch();

        virtual void new_persona(const NewPersonaCommand &cmd) =0;
        virtual void install_application(const InstallApplicationCommand &cmd) =0;

        virtual void register_app(const RegisterApplicationCommand &cmd) =0;
        virtual void list_applications(const ListApplicationsCommand &cmd) =0;

        virtual void join_flock(const JoinFlockCommand &cmd) =0;
      };

      class Response {
      public:
        virtual ~Response();

        typedef uint16_t ResponseCode;

        Response(ProtoParser &p);
        inline Response(ResponseCode sts)
          : m_status(sts) {
        }

        struct Codes {
          static const ResponseCode success = 0;

          static const ResponseCode unknown_error = 1;
          static const ResponseCode unimplemented = 2;
          static const ResponseCode invalid_uri   = 3;
          static const ResponseCode app_data      = 4;
          static const ResponseCode unavailable   = 5;
          static const ResponseCode manifest_not_found = 6;
          static const ResponseCode unknown_uri_scheme = 7;
          static const ResponseCode invalid_manifest   = 8;
          static const ResponseCode no_more_data = 9;
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

      class NewPersonaResponse : public Response {
      public:
        inline NewPersonaResponse(const backend::PersonaId &id)
          : Response(Response::Codes::success), m_id(id) {
        }
        NewPersonaResponse(ProtoParser &p);

        inline const backend::PersonaId &id() const { return m_id; }

      protected:
        virtual void write_data(ProtoBuilder &builder) const;

      private:
        backend::PersonaId m_id;
      };

      class ApplicationResultResponse : public Response {
      public:
        inline ApplicationResultResponse()
          : Response(Response::Codes::no_more_data) {
        };
        inline ApplicationResultResponse(const application::ApplicationIdentifier &id,
                                         const std::string &name)
          : Response(Response::Codes::success),
            m_app_id(id), m_name(name) {
        };
        ApplicationResultResponse(ProtoParser &p);

        inline const application::ApplicationIdentifier &app_id() const { return m_app_id; }
        inline const std::string &name() const { return m_name; }

        inline bool is_end() const { return status() == Response::Codes::no_more_data; }

      protected:
        virtual void write_data(ProtoBuilder &builder) const;

      private:
        application::ApplicationIdentifier m_app_id;
        std::string m_name;
      };
    }
  }
}

#endif
