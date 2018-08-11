#ifndef __stork_container_bridge_HPP__
#define __stork_container_bridge_HPP__

#include "../nix.hpp"

namespace stork {
  namespace container {
    class BridgeController {
    public:
      BridgeController(nix::NixStore &nix);
      ~BridgeController();

      // Create a new veth pair, one in the bridge, one outside the bridge

    private:
      static int main(void *comm);

      nix::NixStore &m_nix_store;
      int m_netns_fd, m_userns_fd;
    };
  }
}

#endif
