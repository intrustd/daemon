#include <boost/bind.hpp>

#include "backend.hpp"

namespace stork {
  namespace flock {
    namespace flockd {
      IBackend::~IBackend() {
      }

      MemoryBackend::MemoryBackend(boost::asio::io_service &svc)
        : m_service(svc), m_strand(svc) {
      }

      MemoryBackend::~MemoryBackend() {
      }

      void MemoryBackend::async_register_device(std::shared_ptr<RegisteredDeviceInfo> rdi,
                                                std::function<void(error_code)> cb) {
        m_strand.dispatch([this, rdi, cb{std::move(cb)}] () {
            auto found(m_devices.find(rdi->name()));
            if ( found == m_devices.end() ||
                 found->second.expired() ) {
              m_devices[rdi->name()] = rdi;
              m_service.post(boost::bind(cb, success));
            } else {
              m_service.post(boost::bind(cb, device_already_registered));
            }
          });
      }

      void MemoryBackend::async_find_device(const std::string &name,
                                            std::function<void(std::shared_ptr<RegisteredDeviceInfo>)> cb) {
        m_strand.dispatch([this, cb{std::move(cb)}, name] () {
            auto found(m_devices.find(name));
            if ( found == m_devices.end() ) {
              cb(nullptr);
            } else {
              auto result(found->second.lock());
              if ( result )
                cb(result);
              else {
                m_devices.erase(found); // Lazily remove entries
                cb(nullptr);
              }
            }
          });
      }
    }
  }
}
