#ifndef __stork_container_init_HPP__
#define __stork_container_init_HPP__

namespace stork {
  namespace container {
    class ContainerService {
    public:
      ContainerService(int comm_fd);
      ~ContainerService();

      void handshake(int tun_fd);
      void serve();

    private:
      int m_comm_fd;
    };

    class Init {
    public:
      Init(int argc, const char **argv);

      int run();

      inline bool is_valid() const { return m_tun_fd > 0 && m_comm_fd > 0; }

    private:
      void usage(const char *err) const;

      int m_tun_fd, m_comm_fd;
    };
  }
}

#endif
