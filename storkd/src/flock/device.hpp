#ifndef __stork_flock_device_HPP__
#define __stork_flock_device_HPP__

#include <boost/chrono.hpp>
#include <string>

#include "proto.hpp"
#include "../backend.hpp"

namespace stork {
  namespace flock {
    class ILiveDevice {
    public:
      virtual ~ILiveDevice() { };

      virtual void gather_personas(std::function<void(boost::system::error_code, stork::proto::flock::LoginToDeviceResponse &&rsp)> cb) =0;
      virtual void send_login_to_device(backend::LoginCredentials &&creds,
                                        std::function<void(boost::system::error_code, proto::flock::Response::ResponseCode,
                                                           const std::string &token)> cb) =0;

      virtual void send_dial(proto::flock::DialSessionCommand &&cmd,
                             std::function<void(boost::system::error_code, const proto::flock::Response &)> cb) =0;
    };

    class RegisteredDeviceInfo {
    public:
      inline RegisteredDeviceInfo(const std::string &name,
                                  const std::string &login_token,
                                  boost::chrono::seconds login_token_ttl,
                                  std::shared_ptr<ILiveDevice> live_device)
        : m_name(name),
          m_login_token(login_token),
          m_login_token_ttl(login_token_ttl),
          m_live_device(live_device) {
      }

      inline const std::string &name() const { return m_name; }
      inline std::shared_ptr<ILiveDevice> live_device() const { return m_live_device; }

      inline void connection_closing() {
        // Breaks the circular reference that keeps these alive
        m_live_device.reset();
      }

    private:
      std::string m_name;
      std::string m_login_token;
      boost::chrono::seconds m_login_token_ttl;

      std::shared_ptr<ILiveDevice> m_live_device;
    };
  }
}

#endif
