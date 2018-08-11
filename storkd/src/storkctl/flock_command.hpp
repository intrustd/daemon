#ifndef __stork_flock_command_HPP__
#define __stork_flock_command_HPP__

#include "command.hpp"

namespace stork {
  namespace storkctl {
    class FlockCommand : public ApiCommandMixin {
    public:
      virtual ~FlockCommand();

      const uri::Uri &flock_uri() const { return m_flock_uri; }

    protected:
      FlockCommand(int argc, const char **argv);

      virtual bool api_required() const;
      virtual void build_options_description();

      uri::Uri m_flock_uri;
    };

    class JoinFlockCommand : public FlockCommand {
    public:
      inline JoinFlockCommand(int argc, const char **argv)
        : FlockCommand(argc, argv) {
      }
      virtual ~JoinFlockCommand();

      virtual int run();

      static inline Command *build(int argc, const char **argv) {
        return new JoinFlockCommand(argc, argv);
      }
    };
  }
}

#endif
