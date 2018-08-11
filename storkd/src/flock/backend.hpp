#ifndef __stork_flock_backend_HPP__
#define __stork_flock_backend_HPP__

#include <boost/asio.hpp>
#include "device.hpp"

namespace stork {
  namespace flock {
    namespace flockd {

      class IBackend {
      public:
        typedef enum error_code_t {
          success = 0,
          device_already_registered = 1,
          device_busy = 2
        } error_code;

        virtual ~IBackend();

        virtual void async_register_device(std::shared_ptr<RegisteredDeviceInfo> rdi,
                                           std::function<void(error_code)> cb) =0;
        virtual void async_find_device(const std::string &name,
                                       std::function<void(std::shared_ptr<RegisteredDeviceInfo>)> cb) =0;
};

      class MemoryBackend : public IBackend {
      public:
        MemoryBackend(boost::asio::io_service &svc);
        virtual ~MemoryBackend();

        virtual void async_register_device(std::shared_ptr<RegisteredDeviceInfo> rdi,
                                           std::function<void(error_code)> cb);
        virtual void async_find_device(const std::string &name,
                                       std::function<void(std::shared_ptr<RegisteredDeviceInfo>)> cb);

      private:
        boost::asio::io_service &m_service;
        boost::asio::io_service::strand m_strand;
        std::unordered_map<std::string, std::weak_ptr<RegisteredDeviceInfo> > m_devices;
      };
    }
  }
}

#endif
