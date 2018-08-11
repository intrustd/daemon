#ifndef __stork_peer_webrtc_HPP__
#define __stork_peer_webrtc_HPP__

#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <cstdint>

namespace stork {
  namespace peer {
    // Data structures for https://tools.ietf.org/html/draft-ietf-rtcweb-data-protocol-09
    class WebRTCOpenMessage {
    public:
      inline std::uint8_t message_type() const { return m_message_type; }
      inline std::uint8_t is_open_msg() const { return message_type() == 3; }

      inline std::string label() const { return std::string(m_var_data, m_var_data + ntohs(m_label_length)); }
      inline std::string protocol() const {
        const char *label_end(m_var_data + ntohs(m_label_length));
        return std::string(label_end, label_end + ntohs(m_protocol_length));
      }

    private:
      std::uint8_t m_message_type;
      std::uint8_t m_channel_type;
      std::uint16_t m_priority;
      std::uint32_t m_reliability;
      std::uint16_t m_label_length, m_protocol_length;
      char m_var_data[];
    } __attribute__ ((packed));

    class WebRTCDataChannel;

    class IWebRTCConnectionDelegate {
    public:
      virtual ~IWebRTCConnectionDelegate();

      virtual void on_data_channel(std::shared_ptr<WebRTCDataChannel> data_channel) =0;
      virtual void on_close() =0;
    };

    class IWebRTCDataChannelDelegate {
    public:
      virtual ~IWebRTCDataChannelDelegate();

      virtual void on_error(boost::system::error_code ec) =0;
      virtual void on_close() =0;
      virtual void on_message(const std::vector<std::uint8_t> &msg) =0;

    protected:
      inline void attach(std::shared_ptr<WebRTCDataChannel> channel) {
        m_associated = channel;
      }

      std::shared_ptr<WebRTCDataChannel> m_associated;

      friend class WebRTCDataChannel;
    };

    class WebRTCConnectionBase {
    public:
      WebRTCConnectionBase(bool is_dtls_server);

      inline bool has_delegate() const { return !!m_delegate; }

      void set_webrtc_delegate(std::shared_ptr<IWebRTCConnectionDelegate> new_delegate);

    protected:
      void do_close(boost::system::error_code ec);
      void dispatch_msg(std::uint16_t stream_id, std::uint32_t ppid, const std::uint8_t *begin, std::size_t sz);

      inline bool stream_can_open(std::uint16_t s) const {
        if ( m_is_dtls_server ) {
          return s % 2 == 0;
        } else
          return s % 2 == 1;
      }

      bool m_is_dtls_server;

      std::shared_ptr<IWebRTCConnectionDelegate> m_delegate;

      std::unordered_map<std::uint16_t, std::shared_ptr<WebRTCDataChannel> > m_data_channels;
    };

    class WebRTCDataChannel {
    public:
      WebRTCDataChannel(const std::string &label, const std::string &protocol);

      void set_delegate(std::shared_ptr<IWebRTCDataChannelDelegate> new_delegate);

      inline const std::string &webrtc_protocol() const { return m_webrtc_protocol; }
      inline const std::string &webrtc_channel_name() const { return m_webrtc_channel_name; }

    private:
      void dispatch_msg(std::uint32_t ppid, const std::uint8_t *base, std::size_t sz);

      std::shared_ptr<IWebRTCDataChannelDelegate> m_delegate;

      std::string m_webrtc_protocol, m_webrtc_channel_name;
      friend class WebRTCConnectionBase;
    };

    // WebRTC Sctp connection adapter
    template<typename Socket>
    class WebRTCConnection : public WebRTCConnectionBase,
                             public std::enable_shared_from_this< WebRTCConnection<Socket> > {
    public:
      WebRTCConnection(Socket s, bool is_dtls_server)
        : WebRTCConnectionBase(is_dtls_server), m_socket(std::move(s)) {
      }

      void start() {
        auto shared(this->shared_from_this());
        m_socket.async_recv_msg([shared] (boost::system::error_code ec, const auto &msg) {
            if ( ec ) {
              shared->do_close(ec);
            } else {
              shared->dispatch_msg(msg.stream_id(), msg.ppid(), msg.data(), msg.size());
              shared->start();
            }
          });
      }

    private:
      Socket m_socket;
    };
  }
}

#endif
