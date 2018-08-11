#include <boost/log/trivial.hpp>

#include "webrtc.hpp"

namespace stork {
  namespace peer {
    static constexpr std::uint32_t WEBRTC_CONTROL_PPID(50);

    IWebRTCConnectionDelegate::~IWebRTCConnectionDelegate() { }
    IWebRTCDataChannelDelegate::~IWebRTCDataChannelDelegate() { }

    inline std::uint16_t calc_stream_base(std::uint16_t s) {
      return s & 0xFFFE;
    }

    // WebRTCDataChannel
    WebRTCDataChannel::WebRTCDataChannel(const std::string &label, const std::string &protocol)
      : m_webrtc_protocol(protocol), m_webrtc_channel_name(label) {
    }

    void WebRTCDataChannel::set_delegate(std::shared_ptr<IWebRTCDataChannelDelegate> new_delegate) {
      if ( m_delegate ) {
        BOOST_LOG_TRIVIAL(error) << "WebRTCChannel::set_delegate: skipping, because delegate is already set";
      } else
        m_delegate = new_delegate;
    }

    void WebRTCDataChannel::dispatch_msg(std::uint32_t ppid, const std::uint8_t *base, std::size_t sz) {
    }

    // WebRTCConnectionBase
    WebRTCConnectionBase::WebRTCConnectionBase(bool is_dtls_server)
      : m_is_dtls_server(is_dtls_server) {
    }

    void WebRTCConnectionBase::set_webrtc_delegate(std::shared_ptr<IWebRTCConnectionDelegate> new_delegate) {
      if ( m_delegate ) {
        BOOST_LOG_TRIVIAL(error) << "WebRTCConnectionBase::set_webrtc_delegate: delegate already set";
      } else
        m_delegate = new_delegate;
    }

    void WebRTCConnectionBase::do_close(boost::system::error_code ec) {
      if ( m_delegate )
        m_delegate->on_close();
      m_delegate.reset();
    }

    void WebRTCConnectionBase::dispatch_msg(std::uint16_t stream_id, std::uint32_t ppid,
                                            const std::uint8_t *begin, std::size_t sz) {
      std::uint16_t stream_base(calc_stream_base(stream_id));

      auto chan_i(m_data_channels.find(stream_base));

      if ( chan_i == m_data_channels.end() ) {
        if ( stream_can_open(stream_id) ) {
          // Attempt to parse the WebRTC open message
          if ( ppid == WEBRTC_CONTROL_PPID && sz >= sizeof(WebRTCOpenMessage) ) {
            const WebRTCOpenMessage *open_msg((const WebRTCOpenMessage *) begin);

            if ( open_msg->is_open_msg() ) {
              BOOST_LOG_TRIVIAL(debug) << "Received webrtc open message";

              auto chan(std::make_shared<WebRTCDataChannel>(open_msg->label(), open_msg->protocol()));
              m_data_channels[stream_base] = chan;

              // TODO send ACK

              // Dispatch
              if ( m_delegate )
                m_delegate->on_data_channel(chan);
            }
          } else
            BOOST_LOG_TRIVIAL(error) << "Skipping channel creation because the open message was malformed";
        }
      } else {
        chan_i->second->dispatch_msg(ppid, begin, sz);
      }
    }
  }
}
