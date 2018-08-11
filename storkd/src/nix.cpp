#include <boost/log/trivial.hpp>
#include <sstream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "nix.hpp"

namespace stork {
  namespace nix {
    NixStore::NixStore() {
    }

    boost::filesystem::path NixStore::operator[](const std::string &pkg_name) const {
      auto i(m_nixpkgs.find(pkg_name));
      if ( i == m_nixpkgs.end() ) {
        throw std::invalid_argument("Nix package was not built");
      }

      return i->second;
    }

    void NixStore::build(const std::string &s) {
      BOOST_LOG_TRIVIAL(debug) << "Building nix package " << s;

      int p[2];
      int err(pipe(p));
      if ( err == -1 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not create pipe: " << ec;
        return;
      }

      pid_t pid(fork());
      if ( pid == 0 ) {
        close(p[0]);

        dup2(p[1], STDOUT_FILENO);
        close(STDIN_FILENO);

        std::stringstream pkg_arg;
        pkg_arg << "pkgs." << s;
        execlp("nix-build", "nix-build", "<nixpkgs>", "-A", pkg_arg.str().c_str(), "--no-out-link", NULL);
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not execute nix-build: " << ec;
      } else {
        close(p[1]);

        // Parent
        int sts;
        err = waitpid(pid, &sts, 0);

        if ( sts != 0 ) {
          BOOST_LOG_TRIVIAL(error) << "Nix-build returned status: " << sts;
          return;
        }

        char path[PATH_MAX];
        err = read(p[0], path, PATH_MAX);
        if ( err == -1 ) {
          auto ec(errno);
          BOOST_LOG_TRIVIAL(error) << "Could not read path from pipe: " << ec;
        }

        close(p[0]);

        m_nixpkgs[s] = boost::filesystem::path(std::string(path, path + err - 1));
      }
    }
  }
}
