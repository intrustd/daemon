#ifndef __stork_peer_service_HPP__
#define __stork_peer_service_HPP__

namespace stork {
  namespace appliance { class Appliance; }
  namespace peer {
    template<typename Socket>
    class PeerService {
    public:
      // TODO authentication / login information
      PeerService(boost::asio::io_service &svc, appliance::Appliance &app,
                  Socket &&s);

      void async_start();

    private:
      Socket m_socket;
    };
  }
}

#endif
