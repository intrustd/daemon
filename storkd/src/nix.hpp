#ifndef __stork_nix_HPP__
#define __stork_nix_HPP__

#include <boost/filesystem/path.hpp>
#include <string>
#include <unordered_map>

namespace stork {
  namespace nix {
    class NixStore {
    public:
      NixStore();

      void build(const std::string &s);

      boost::filesystem::path operator[](const std::string &pkg_name) const;

    private:
      std::unordered_map<std::string, boost::filesystem::path> m_nixpkgs;
    };
  }
}

#endif
