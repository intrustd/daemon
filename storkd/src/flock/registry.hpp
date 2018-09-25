#ifndef __stork_flock_registry_HPP__
#define __stork_flock_registry_HPP__

#include <boost/asio.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/tss.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <memory>
#include <vector>

#include "../crypto/context.hpp"
#include "../crypto/certificate.hpp"
#include "appliance_proto.hpp"
#include "configuration.hpp"

namespace stork {
  namespace flock {
    namespace flockd {
      class ApplianceRegistry;

      class IIceSignaller {
      public:
        virtual void on_ice_error() =0;
        virtual void on_ice_candidate(const std::string &c) =0;
        virtual void on_ice_candidates_done() =0;
      };

      class RegisteredDeviceInfo {
      public:
        RegisteredDeviceInfo(ApplianceRegistry &reg, const std::string &name,
                             const crypto::Key &kp);

        ~RegisteredDeviceInfo();

        void update_persona_cache(std::string &&persona_info,
                                  boost::posix_time::time_duration m_keep_alive);

        void touch();
        std::shared_ptr<IIceSignaller> get_connection(std::uint32_t ctag);

        inline const crypto::Key &public_key() const { return m_appliance_key; }

      private:
        void expiry_timer_expires(boost::system::error_code ec);
        void device_timer_expires(boost::system::error_code ec);

        std::string m_name;
        ApplianceRegistry &m_registry;

        crypto::Key m_appliance_key;

        boost::asio::deadline_timer m_persona_cache_expiry_timer, m_device_timer;

        boost::mutex m_device_lock;

        bool m_cached_personas : 1;
        std::string m_cached_persona_info;

        std::unordered_map<std::uint32_t, std::shared_ptr<IIceSignaller> > m_connections;
      };

      class ApplianceRegistry {
      public:
        ApplianceRegistry(boost::asio::io_service &svc, const Configuration &conf);

        inline boost::asio::io_service &service() { return m_service; }

        // Launces the registration server on the given port with the given options
        void start();

        std::shared_ptr<RegisteredDeviceInfo> find_device(const std::string &name);

      private:
        void unregister_appliance(const std::string &name);

        void start_serve();
        void start_serve_after_lock();
        void serve_next(std::shared_ptr< std::vector<std::uint8_t> > b);
        std::shared_ptr< std::vector<std::uint8_t> > alloc_packet();
        void process_packet(boost::asio::ip::udp::endpoint ep,
                            std::vector<std::uint8_t> &pkt);

        void decrypt_packet(const std::vector<std::uint8_t> &in_data,
                            std::uint8_t *out_data, std::size_t &out_sz,
                            std::error_code &ec);
        void send_response(const ApplianceMessage &rsp);

        static constexpr std::size_t DEF_PKT_SZ = 2048;
        static constexpr int MAX_INFLIGHT = 10;

        boost::asio::io_service &m_service;
        const Configuration &m_conf;
        boost::asio::ip::udp::socket m_socket;

        boost::asio::ip::udp::endpoint m_packet_endpoint;
        boost::thread_specific_ptr<crypto::KeyContext> m_packet_decrypter;

        boost::mutex m_inflight_mutex;
        int m_inflight;
        std::vector< std::shared_ptr< std::vector<std::uint8_t> > > m_released_inflight;

        boost::mutex m_shards_mutex;
        std::vector<boost::asio::ip::udp::endpoint> m_shards;

        boost::mutex m_appliances_mutex;
        std::unordered_map<std::string, std::shared_ptr<RegisteredDeviceInfo> > m_appliances;

        friend class RegisteredDeviceInfo;
      };
    }
  }
}

#endif
