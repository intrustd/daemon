#ifndef __stork_application_command_HPP__
#define __stork_application_command_HPP__

#include "command.hpp"
#include "persona_command.hpp"

#include "../application/application.hpp"

namespace stork {
  namespace storkctl {
    class RegisterApplicationCommand : public ApiCommandMixin {
    public:
      virtual ~RegisterApplicationCommand();

      virtual int run();

      static inline Command *build(int argc, const char **argv) {
        return new RegisterApplicationCommand(argc, argv);
      }

    protected:
      RegisterApplicationCommand(int argc, const char **argv);

      virtual bool api_required() const;
      virtual void build_options_description();

    private:
      std::string m_manifest_url;
    };

    class ListApplicationsCommand : public ApiCommandMixin {
    public:
      virtual ~ListApplicationsCommand();

      virtual int run();

      static inline Command *build(int argc, const char **argv) {
        return new ListApplicationsCommand(argc, argv);
      }

    protected:
      ListApplicationsCommand(int argc, const char **argv);

      virtual bool api_required() const;
      virtual void build_options_description();
    };

    class InstallApplicationCommand : public ApiCommandMixin {
    public:
      virtual ~InstallApplicationCommand();

      virtual int run();

      static inline Command *build(int argc, const char **argv) {
        return new InstallApplicationCommand(argc, argv);
      }

    protected:
      InstallApplicationCommand(int argc, const char **argv);

      virtual bool api_required() const;
      virtual void build_options_description();

      backend::PersonaId m_persona_id;
      application::ApplicationIdentifier m_app_id;
    };
  }
}

#endif
