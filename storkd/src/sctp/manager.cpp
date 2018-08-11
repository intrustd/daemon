#include <boost/log/utility/manipulators/dump.hpp>
#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>

#include "manager.hpp"
#include "proto.hpp"
#include "packet.hpp"
#include "../random.hpp"

namespace stork {
  namespace sctp {
    template<typename T, typename... Args>
    class weak_fn {
    public:
      using FnType = void (T::*)(Args...);
      weak_fn(FnType fn, std::weak_ptr<T> p)
        : m_this(p), m_fn(fn) {
      }

      void operator() (const Args &... args) {
        auto _this(m_this.lock());
        if ( _this ) {
          (_this.get()->*m_fn)(args...);
        } else
          return;
      }

    private:
      std::weak_ptr<T> m_this;
      FnType m_fn;
    };

    ISctpAcceptorControl::~ISctpAcceptorControl() { }

    SctpManagerBase::SctpManagerBase(boost::asio::io_service &svc,
                                     std::size_t max_size, std::size_t max_packet_queue_length)
      : m_packets_processing(0),
        m_state(initialized), m_max_packet_size(max_size),
        m_max_packet_queue_length(max_packet_queue_length),
        m_mac_key_ttl(60), m_mac_renewal_timer(svc),
        m_cur_mac(0) {
    }

    SctpManagerBase::~SctpManagerBase() {
      boost::unique_lock ports_l(m_ports_mutex);

      bool ports_alive(false);
      for ( auto port_ptr : m_ports ) {
        if ( port_ptr.second.lock() ) {
          ports_alive = true;
          break;
        }
      }

      if ( ports_alive )
        BOOST_LOG_TRIVIAL(warning) << "SctpManager destroyed while ports are alive";
    }

    // Management

    std::shared_ptr<SctpOpenPort> SctpManagerBase::get_port(SctpPort port, bool do_open) {
      boost::upgrade_lock ports_l(m_ports_mutex);
      auto i(m_ports.find(port));
      std::shared_ptr<SctpOpenPort> open_port;
      if ( i == m_ports.end() ) {
        if ( do_open ) {
          open_port = std::make_shared<SctpOpenPort>(shared_base_from_this());

          boost::upgrade_to_unique_lock ports_write_l(ports_l);
          m_ports.insert(std::make_pair(port, open_port));
        }
      } else {
        open_port = i->second.lock();
        if ( !open_port ) {
          if ( do_open ) {
            open_port = std::make_shared<SctpOpenPort>(shared_base_from_this());

            boost::upgrade_to_unique_lock ports_write_l(ports_l);
            m_ports.insert(std::make_pair(port, open_port));
          }
        }
      }
      return open_port;
    }

    std::pair<SctpPort, std::shared_ptr<SctpOpenPort> > SctpManagerBase::choose_arbitrary_port() {
      boost::shared_lock ports_l(m_ports_mutex);
      boost::random_device rd;
      boost::random::uniform_int_distribution<SctpPort> ports_gen(49152, 65535);
      std::size_t tries_left = 100;
      SctpPort port(0);

      // Generate random port until we find one that is open
      for ( port = ports_gen(rd);
            m_ports.find(port) != m_ports.end() && tries_left != 0;
            port = ports_gen(rd), tries_left -- );

      if ( tries_left == 0 ) {
        return std::make_pair(0, nullptr);
      } else {
        auto open_port(get_port(port));
        return std::make_pair(port, open_port);
      }
    }

    // void SctpManagerBase::bind_acceptor_to_address(const boost::asio::ip::addressSctpPort port, std::shared_ptr<ISctpAcceptorControl> acceptor_ptr,
    //                                             boost::system::error_code &ec) {
    //   auto open_port(get_port(port));
    //   if ( !open_port ) {
    //     ec = boost::system::error_code(ENOMEM, boost::system::generic_category());
    //   } else
    //     return;
    // }

    // Runtime

    void SctpManagerBase::start() {
        boost::shared_lock options_l(m_options_mutex);

        if ( m_state == initialized ) {
          m_state = started;
          options_l.release()->unlock_shared();

          m_started_at = time(NULL);
          renew_mac();

          receive_next_packet();
        } else
          BOOST_LOG_TRIVIAL(warning) << "SctpManager::start called on started socket";
    }

    void SctpManagerBase::send_packet(boost::asio::const_buffer b) {
      boost::unique_lock l(m_socket_mutex);
      do_send(b);
    }

    void SctpManagerBase::stop() {
      boost::unique_lock options_l(m_options_mutex);
      m_state = initialized;
      options_l.release()->unlock();
      m_mac_renewal_timer.cancel();

      boost::unique_lock ports_l(m_ports_mutex);

      for ( auto port : m_ports ) {
        auto port_live(port.second.lock());
        if ( port_live )
          service().post(boost::bind(&SctpOpenPort::cancel, port_live));
      }
    }

    void SctpManagerBase::start_mac_timer() {
      m_mac_renewal_timer.expires_from_now(boost::posix_time::seconds(m_mac_key_ttl));
      m_mac_renewal_timer.async_wait(boost::bind(&SctpManagerBase::renew_mac, shared_base_from_this()));
    }

    void SctpManagerBase::renew_mac() {
      boost::unique_lock l(m_options_mutex);

      m_mac_updated_at = time(NULL);

      if ( m_cur_mac == 0 )
        m_cur_mac = PREVIOUS_MACS - 1;
      else
        m_cur_mac--;

      BOOST_LOG_TRIVIAL(debug) << "Renewing mac";
      std::copy(util::random_iterator<std::uint8_t>(sizeof(mac_key_type)),
                util::random_iterator<std::uint8_t>(),
                m_previous_mac_keys[m_cur_mac]);

      start_mac_timer();
    }

    void SctpManagerBase::current_mac_key(std::uint8_t *key_out, time_t &cur_time) {
      boost::shared_lock l(m_options_mutex);
      cur_time = time(NULL);

      if ( (cur_time - m_mac_updated_at) > m_mac_key_ttl ) {
        BOOST_LOG_TRIVIAL(warning) << "Using old mac key because the key was not updated";
        cur_time = m_mac_updated_at - 1;
      }

      std::copy(m_previous_mac_keys[m_cur_mac], m_previous_mac_keys[m_cur_mac] + sizeof(mac_key_type), key_out);
    }

    bool SctpManagerBase::mac_key_at_time(std::uint8_t *key_out, time_t at_time) {
      boost::shared_lock l(m_options_mutex);

      if ( at_time > m_mac_updated_at ) return false;
      if ( (m_mac_updated_at - at_time) > (m_mac_key_ttl * PREVIOUS_MACS) ) return false;

      unsigned int which_key((m_mac_updated_at - at_time) / m_mac_key_ttl);
      unsigned int which_mac_index(m_cur_mac);
      for ( unsigned int i = 0; i < which_key; ++ i) {
        if ( which_mac_index == 0 ) which_mac_index = PREVIOUS_MACS - 1;
        else which_mac_index--;
      }

      std::copy(m_previous_mac_keys[which_mac_index], m_previous_mac_keys[which_mac_index] + sizeof(mac_key_type), key_out);
      return true;
    }

    void SctpManagerBase::on_recv_packet(boost::system::error_code ec, std::size_t bs) {
      BOOST_LOG_TRIVIAL(debug) << "SCTP Manager receives packet";
      if ( ec ) {
        BOOST_LOG_TRIVIAL(error) << "SctpManager error: " << ec;
        stop();
      } else {
        // Add packet to packets queue
        m_incoming_packet.resize(bs);
        if ( push_packet() ) {
          service().post(weak_fn< SctpManagerBase >(&SctpManagerBase::process_next_packet, weak_base_from_this()));
          receive_next_packet();
        } else
          BOOST_LOG_TRIVIAL(debug) << "Ignoring packet because there is no space in our queue";
      }
    }

    void SctpManagerBase::on_packet_sent(boost::system::error_code ec, std::size_t bs) {
      if ( ec ) {
        BOOST_LOG_TRIVIAL(error) << "Could not send response: " << ec;
      } else
        BOOST_LOG_TRIVIAL(info) << "Sent packet of size " << bs << " bytes";
    }

    void SctpManagerBase::receive_next_packet() {
      BOOST_LOG_TRIVIAL(debug) << "receive_next_packet: start";
      boost::unique_lock socket_l(m_socket_mutex);

      if ( !m_available_packets.empty() ) {
        m_incoming_packet = std::move(m_available_packets.front());
        m_available_packets.pop_front();
      }

      m_incoming_packet.resize(m_max_packet_size);
      do_receive_next();
      BOOST_LOG_TRIVIAL(debug) << "DOne receiving next";
    }

    void SctpManagerBase::give_up_packet(std::vector<std::uint8_t> &&pkt) {
      boost::unique_lock socket_l(m_socket_mutex);
      m_available_packets.emplace_back(std::move(pkt));
      socket_l.release()->unlock();

      boost::unique_lock packet_queue_l(m_packet_queue_mutex);
      if ( (m_packets_processing--) == m_max_packet_queue_length ) {
        packet_queue_l.release()->unlock();
        receive_next_packet();
      }
    }

    bool SctpManagerBase::push_packet() {
      boost::upgrade_lock packet_queue_l(m_packet_queue_mutex);
      if ( m_packets_processing >= m_max_packet_queue_length ) {
        BOOST_LOG_TRIVIAL(error) << "push_packet: " << m_packets_processing << " >= " << m_max_packet_queue_length;
        return false;
      } else {
        boost::upgrade_to_unique_lock packet_queue_write_l(packet_queue_l);
        m_packets_processing++;

        m_packet_queue.emplace_back(m_incoming_source, std::move(m_incoming_packet));
        return true;
      }
    }

    bool SctpManagerBase::pop_next_packet(boost::asio::ip::address &source, std::vector<std::uint8_t> &packet) {
      boost::upgrade_lock packet_queue_l(m_packet_queue_mutex);
      if ( m_packet_queue.empty() )
        return false;
      else {
        BOOST_LOG_TRIVIAL(debug) << "process_next_packet: getting packet";
        boost::upgrade_to_unique_lock packet_queue_write_l(packet_queue_l);
        packet = std::move(m_packet_queue.front().second);
        m_packet_queue.pop_front();
        BOOST_LOG_TRIVIAL(debug) << "process_next_packet: popped packet";
      }
      return true;
    }

    void SctpManagerBase::process_next_packet() {
      BOOST_LOG_TRIVIAL(debug) << "process_next_packet";
      std::vector<std::uint8_t> packet;
      boost::asio::ip::address source;
      if ( pop_next_packet(source, packet) ) {
        try {
          process_packet(source, packet);
        } catch ( std::exception &e ) {
          give_up_packet(std::move(packet));
          throw;
        }
        give_up_packet(std::move(packet));
      } else
        BOOST_LOG_TRIVIAL(warning) << "process_next_packet: packet queue empty";

    }

    void SctpManagerBase::process_packet(const boost::asio::ip::address &from,
                                         std::vector<std::uint8_t> &pkt) {
      BOOST_LOG_TRIVIAL(debug) << "SctpManager processing packet: " << boost::log::dump(pkt.data(), pkt.size());

      SctpHeaderPtr hdr(pkt);
      BOOST_LOG_TRIVIAL(debug) << "SctpManager: this packet is destined for " << hdr->destination_port();

      if ( hdr.verify_checksum() ) {
        m_response_builder.reset(hdr, 1500);
        SctpChunkProcessor processor(*this, m_response_builder, from, hdr);

        for ( auto &chunk : hdr ) {
          chunk.dispatch(processor);
        }

        if ( processor.process() ) {
          auto response(m_response_builder.asio_buffer());
          BOOST_LOG_TRIVIAL(debug) << "SctpManager: would respond " << boost::log::dump(boost::asio::buffer_cast<const std::uint8_t*>(response), boost::asio::buffer_size(response));
          do_send(response);
        } else
          BOOST_LOG_TRIVIAL(warning) << "Ignoring packet due to packet processing error";
      } else
        BOOST_LOG_TRIVIAL(debug) << "Ignoring packet due to checksum violation: expect " << hdr.expected_checksum() << ", received " << hdr->actual_checksum();
    }

    // SctpAssociationControlBase
    SctpAssociationControlBase::SctpAssociationControlBase(boost::asio::io_service &svc,
                                                           const SctpHeader &hdr,
                                                           const StateCookieData &cookie)
      : m_source_port(hdr.destination_port()), m_destination_port(hdr.source_port()),
        m_remote_verification_tag(cookie.remote_verification_tag()),
        m_local_verification_tag(cookie.local_verification_tag()),
        m_cum_remote_tsn(cookie.remote_tsn()), m_highest_remote_tsn(cookie.remote_tsn()),
        m_local_tsn(cookie.local_tsn()),

        m_local_rwnd(cookie.local_rwnd()), m_remote_rwnd(cookie.remote_rwnd()),

        m_num_inbound(cookie.ib_streams()), m_num_outbound(cookie.ob_streams()),

        m_sack_debounce_interval(boost::posix_time::milliseconds(200)), // As recommended
        m_sack_required(false), m_pkts_received(0),

        m_sack_timer(svc), m_sack_packet(0, 0, 0) {
    }

    SctpAssociationControlBase::~SctpAssociationControlBase() {
    }

    void SctpAssociationControlBase::cancel() {
      m_sack_timer.cancel();
    }

    std::uint32_t SctpAssociationControlBase::remote_verification_tag() const {
      return m_remote_verification_tag;
    }

    std::uint32_t SctpAssociationControlBase::local_verification_tag() const {
      return m_local_verification_tag;
    }

    DataChunkStatus SctpAssociationControlBase::deliver_chunk(const DataChunk &chunk) {
      BOOST_LOG_TRIVIAL(debug) << "Association receives packet";

      boost::unique_lock l(m_transmission_mutex);
      BOOST_LOG_TRIVIAL(debug) << "Updating cum remote TSN: " << chunk.tsn() << " " << m_cum_remote_tsn;
      if ( chunk.tsn() == (m_cum_remote_tsn + 1) ) {
        m_cum_remote_tsn = chunk.tsn();

        // TODO remove any gaps in the gap buffer
      }
      BOOST_LOG_TRIVIAL(debug) << "CUM remote TSN is now " << chunk.tsn();

      if ( chunk.tsn() > m_highest_remote_tsn ) {
        // TODO Add gap into block if need be
        m_highest_remote_tsn = chunk.tsn();

        if ( m_highest_remote_tsn != m_cum_remote_tsn ) {
          BOOST_LOG_TRIVIAL(debug) << "Should add gaps";
        }
      }

      // SACK-IMMEDIATELY extension: https://tools.ietf.org/html/rfc7053
      if ( chunk.sack_immediately() ) {
        m_sack_required = true;
      }

      // Check if this packet is fragmented
      if ( chunk.fragmented() ) {
        BOOST_LOG_TRIVIAL(error) << "TODO: receive fragmented chunk";
        return data_chunk_not_implemented;
      }

      // If this packet is unordered, then deliver the packet immediately
      if ( chunk.unordered() ) {
        return data_chunk_success;
      } else {
        if ( chunk.stream_id() > m_num_inbound )
          return data_chunk_invalid_stream;

        // Otherwise, attempt to find/create stream, if we can't find it return an error code
        try {
          auto &stream(get_stream(chunk.stream_id()));

          return stream.deliver_chunk(chunk);
        } catch ( std::bad_alloc &e ) {
          return data_chunk_out_of_memory;
        }
      }

      return data_chunk_not_implemented;
    }

    void SctpAssociationControlBase::deliver_immediately(SctpDeliveredPacket *pkt) {
      std::unique_ptr<SctpDeliveredPacket> unique_pkt(pkt);
      if ( m_readers.empty() ) {
        // Add to delivery queue
        m_delivery_queue.emplace_back(std::move(unique_pkt));
      } else {
        std::shared_ptr<SctpDeliveredPacket> shared_pkt(unique_pkt.release());
        auto cb(m_readers.front());
        m_readers.pop_front();

        manager()->service().post([cb{std::move(cb)}, shared_pkt] () {
            cb(boost::system::error_code(), *shared_pkt);
          });
      }
    }

    SctpStreamControl &SctpAssociationControlBase::get_stream(SctpStreamId s) {
      auto i(m_streams.find(s));
      if ( i == m_streams.end() ) {
        return m_streams.emplace(std::piecewise_construct, std::forward_as_tuple(s),
                                 std::forward_as_tuple(std::ref(*this), s)).first->second;
      } else
        return i->second;
    }

    void SctpAssociationControlBase::send_sack_if_necessary(SctpPacketBuilder &packet) {
      boost::unique_lock l(m_transmission_mutex);
      m_pkts_received++;

      BOOST_LOG_TRIVIAL(debug) << "send_sack_if_necessary: received " << m_pkts_received << " packet(s)";

      if ( m_pkts_received == 2 || m_sack_required ) {
        m_pkts_received = 0;

        send_sack(packet);
      } else if ( m_pkts_received == 1 ) {
        // We should start the SACK timer so it is sent eventually
        start_sack_timer();
      }
    }

    void SctpAssociationControlBase::start_sack_timer() {
      m_sack_timer.expires_from_now(m_sack_debounce_interval);
      m_sack_timer.async_wait(boost::bind(&SctpAssociationControlBase::force_send_sack, base_shared_from_this(),
                                          boost::placeholders::_1));
    }

    void SctpAssociationControlBase::force_send_sack(boost::system::error_code ec) {
      if ( ec ) return;

      BOOST_LOG_TRIVIAL(debug) << "Sending SACK due to timer";
      boost::unique_lock l(m_transmission_mutex);
      m_sack_packet.reset(m_source_port, m_destination_port, 1500);
      send_sack(m_sack_packet);

      if ( m_sack_packet.overflow() ) {
        BOOST_LOG_TRIVIAL(error) << "Cannot send SACK due to overflow. TODO: signal error";
      } else {
        m_sack_packet.finish();

        manager()->send_packet(m_sack_packet.asio_buffer());
      }
    }

    void SctpAssociationControlBase::send_sack(SctpPacketBuilder &packet) {
      m_sack_timer.cancel();

      packet.emplace_chunk<SelectiveAck>(m_cum_remote_tsn, m_local_rwnd, m_gap_tsns, m_dup_tsns);
      m_dup_tsns.clear();
    }

    bool SctpAssociationControlBase::will_store_packet(const SctpDeliveredPacket &pkt) {
      if ( m_local_rwnd < pkt.size() ) {
        return false;
      } else {
        m_local_rwnd -= pkt.size();
        return true;
      }
    }

    void SctpAssociationControlBase::will_deliver_stored_packet(const SctpDeliveredPacket &pkt) {
      m_local_rwnd += pkt.size();
    }

    // SctpStreamControl
    SctpStreamControl::SctpStreamControl(SctpAssociationControlBase &assoc, SctpStreamId our_id)
      : m_association(assoc), m_this_stream_id(our_id), m_next_ssn(0) {
    }

    SctpStreamControl::~SctpStreamControl() {
      while ( !m_reassembly_queue.empty() ) {
        delete m_reassembly_queue.top();
        m_reassembly_queue.pop();
      }
    }

    DataChunkStatus SctpStreamControl::deliver_chunk(const DataChunk &chunk) {
      auto packet(new SctpDeliveredPacket(m_this_stream_id, chunk));

      if ( chunk.ssn() == m_next_ssn ) {
        // We can deliver this chunk immediately
        //m_association.deliver_immediately(chunk)
        BOOST_LOG_TRIVIAL(debug) << "We will deliver this chunk immediately";
        m_next_ssn++;

        m_association.deliver_immediately(packet);

        deliver_outstanding();
        return data_chunk_success;
      } else {
        if ( m_association.will_store_packet(*packet) ) {
          m_reassembly_queue.push(packet);
          return data_chunk_success;
        } else
          return data_chunk_dropping_packet;
      }
    }

    void SctpStreamControl::deliver_outstanding() {
      while ( !m_reassembly_queue.empty() &&
              m_reassembly_queue.top()->ssn() == m_next_ssn ) {
        m_association.will_deliver_stored_packet(*m_reassembly_queue.top());
        m_association.deliver_immediately(m_reassembly_queue.top());
        m_reassembly_queue.pop();
        m_next_ssn++;
      }
    }

    // SctpDeliveredPacket
    SctpDeliveredPacket::SctpDeliveredPacket(SctpStreamId sid, const DataChunk &chunk)
      : m_stream_id(sid), m_stream_ssn(chunk.ssn()),
        m_ppid(chunk.payload_protocol()),
        m_is_unordered(chunk.unordered())
    {
      m_data.resize(chunk.user_data_size());
      std::copy(chunk.begin(), chunk.end(), m_data.data());
    }
  }
}
