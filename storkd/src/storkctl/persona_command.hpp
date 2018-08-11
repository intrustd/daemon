#ifndef __stork_persona_command_HPP__
#define __stork_persona_command_HPP__

#include "command.hpp"
#include "../backend.hpp"

namespace stork {
  namespace storkctl {
    class NewPersonaCommand : public ApiCommandMixin {
    public:
      virtual ~NewPersonaCommand();

      virtual int run();

      static inline Command *build(int argc, const char **argv) {
        return new NewPersonaCommand(argc, argv);
      }

    protected:
      NewPersonaCommand(int argc, const char **argv);

      virtual bool api_required() const;
      virtual void build_options_description();

    private:
      std::string m_full_name, m_email;
    };
  }
}

#endif
