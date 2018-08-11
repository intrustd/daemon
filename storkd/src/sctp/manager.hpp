#ifndef __stork_sctp_manager_HPP__
#define __stork_sctp_manager_HPP__

#include <memory>
#include <atomic>
#include <deque>
#include <queue>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <list>
#include <ctime>

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/log/trivial.hpp>
#include <boost/thread/shared_mutex.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "../util/array.hpp"
#include "proto.hpp"

namespace stork {
  namespace sctp {
    typedef std::uint16_t SctpPort;

    template<typename Socket>
    class SctpAcceptor;
    template<typename Socket>
    class SctpAssociation;

    class SctpAssociationControlBase;

    class SctpEndpoint {
    public:
      inline SctpEndpoint(const boost::asio::ip::address &a, std::uint16_t port)
        : m_addr(a), m_port(port) {
      }

      inline const boost::asio::ip::address &addr() const { return m_addr; }
      inline std::uint16_t port() const { return m_port; };

    private:
      boost::asio::ip::address m_addr;
      std::uint16_t m_port;
    };

    class ISctpAcceptorControl {
    public:
      virtual ~ISctpAcceptorControl();

      virtual void cancelled() =0;
    };

    class SctpOpenPort;
    class SctpManagerBase {
    public:
      static constexpr std::size_t MAC_KEY_SIZE = 128;
      using mac_key_type = std::uint8_t[MAC_KEY_SIZE];

      SctpManagerBase(boost::asio::io_service &svc, std::size_t max_size = 8 * 1024, std::size_t packet_queue_length = 10);
      ~SctpManagerBase();

      virtual boost::asio::io_service &service() =0;

      void start();

    protected:
      void receive_next_packet();
      virtual void do_receive_next() =0;
      virtual void do_send(boost::asio::const_buffer b) =0;
      virtual std::shared_ptr<SctpManagerBase> shared_base_from_this() =0;
      virtual std::weak_ptr<SctpManagerBase> weak_base_from_this() =0;
      virtual std::shared_ptr<SctpAssociationControlBase> new_association(const SctpHeader &hdr,
                                                                          const StateCookieData &d) =0;

      void send_packet(boost::asio::const_buffer b);

      void stop();
      void on_recv_packet(boost::system::error_code ec, std::size_t bs);
      void on_packet_sent(boost::system::error_code ec, std::size_t bs);
      void give_up_packet(std::vector<std::uint8_t> &&pkt);
      void process_next_packet();
      void process_packet(const boost::asio::ip::address &source, std::vector<std::uint8_t> &pkt);
      bool pop_next_packet(boost::asio::ip::address &source, std::vector<std::uint8_t> &packet);

      /**
       * Pushes the current packet (m_incoming_packet, m_incoming_source) onto the packet queue.
       *
       * @returns true if the packet was successfully pushed, false if there is no space in the
       * queue
       */
      bool push_packet();

      void start_mac_timer();
      void renew_mac();
      void current_mac_key(std::uint8_t *key, time_t &cur_time);
      bool mac_key_at_time(std::uint8_t *key, time_t at_time);

      std::shared_ptr<SctpOpenPort> get_port(SctpPort port, bool do_open=true);
      //      void bind_acceptor_to_address(const boost::asio::ip::address &ip, std::shared_ptr<ISctpAcceptorControl> acceptor_ptr,
      //boost::system::error_code &ec);
      std::pair<SctpPort, std::shared_ptr<SctpOpenPort> > choose_arbitrary_port();

      enum State {
        invalid = 0,
        initialized,
        started
      };

      boost::mutex m_socket_mutex;
      boost::shared_mutex m_packet_queue_mutex;
      std::size_t m_packets_processing;
      std::deque< std::vector<std::uint8_t> > m_available_packets;
      std::deque< std::pair< boost::asio::ip::address, std::vector<std::uint8_t> > > m_packet_queue;
      SctpPacketBuilder m_response_builder;

      boost::shared_mutex m_ports_mutex;
      std::unordered_map< SctpPort, std::weak_ptr< SctpOpenPort > > m_ports;

      boost::shared_mutex m_options_mutex;
      time_t m_started_at, m_mac_updated_at;
      State m_state;
      std::size_t m_max_packet_size, m_max_packet_queue_length;
      unsigned int m_mac_key_ttl;
      boost::asio::deadline_timer m_mac_renewal_timer;

      static constexpr unsigned int PREVIOUS_MACS = 10;
      unsigned int m_cur_mac;
      mac_key_type m_previous_mac_keys[PREVIOUS_MACS];

      std::vector<std::uint8_t> m_incoming_packet;
      boost::asio::ip::address m_incoming_source;

      template <typename Socket>
      friend class SctpAcceptorControl;

      template <typename Socket>
      friend class SctpAssociationControl;

      friend class SctpChunkProcessor;
      friend class SctpAssociationControlBase;
      friend class SctpOpenPort;
    };

    class SctpConnectionRequest {
    public:
      SctpConnectionRequest(boost::asio::io_service &svc);

    private:
      boost::mutex m_lock;

      boost::asio::deadline_timer m_timer;
    };

    class SctpOpenPort {
    public:
      SctpOpenPort(std::shared_ptr<SctpManagerBase> base);
      ~SctpOpenPort();

      using ListenerCallback = std::function<void(boost::system::error_code, std::shared_ptr<SctpAssociationControlBase>)>;
      void listen(std::size_t sz, boost::system::error_code &ec);
      void async_accept(ListenerCallback cb);

      enum AssociationResult {
        association_created,
        association_already_exists,
        association_error_no_mem,
        association_rejected
      };

      AssociationResult receive_association(const boost::asio::ip::address &ip,
                                            const SctpHeader &hdr,
                                            const StateCookieData &d);

      bool is_listening();

      void cancel();

      void bind(std::shared_ptr<ISctpAcceptorControl> a,
                boost::system::error_code &ec);

    private:
      inline bool _is_listening() const {
        return m_listen_queue_length > 0;
      }

      inline std::shared_ptr<SctpAssociationControlBase> find_association(const boost::asio::ip::address &source) {
        auto found(m_associations.find(source));
        if ( found == m_associations.end() )
          return nullptr;
        else
          return found->second;
      }

      std::shared_ptr<SctpManagerBase> m_manager;

      boost::mutex m_port_mutex;

      std::size_t m_listen_queue_length;
      std::deque< std::shared_ptr<SctpAssociationControlBase> > m_listen_queue;
      std::queue<ListenerCallback> m_listeners;

      // May want to use an unordered map
      std::unordered_set< std::shared_ptr<ISctpAcceptorControl> > m_acceptors;

      // TODO change to assoc id
      std::map< boost::asio::ip::address,
                std::shared_ptr<SctpAssociationControlBase> > m_associations;

      friend class SctpChunkProcessor;
    };

    template <typename Socket>
    class SctpManager;

    enum DataChunkStatus {
      data_chunk_success,
      data_chunk_out_of_memory,
      data_chunk_invalid_stream,
      data_chunk_not_implemented,
      data_chunk_dropping_packet
    };

    class SctpDeliveredPacket {
    public:
      SctpDeliveredPacket(SctpStreamId sid, const DataChunk &from);
      inline SctpDeliveredPacket()
        : m_stream_id(0), m_stream_ssn(0), m_is_unordered(false) {
      }

      inline std::uint16_t ssn() const { return m_stream_ssn; }
      inline std::uint16_t stream_id() const { return m_stream_id; }
      inline std::uint32_t ppid() const { return m_ppid; }

      inline const std::uint8_t *data() const { return m_data.data(); }
      inline std::size_t size() const { return m_data.size(); }

    private:
      std::uint16_t m_stream_id, m_stream_ssn;
      std::uint32_t m_ppid;
      std::vector<std::uint8_t> m_data;

      bool m_is_unordered : 1;
    };

    struct SctpComparePacketSsn {
    public:
      bool operator() (SctpDeliveredPacket *a, SctpDeliveredPacket *b) const {
        return a->ssn() > b->ssn();
      }
    };

    struct SctpStreamControl {
    public:
      SctpStreamControl(SctpAssociationControlBase &assoc, SctpStreamId our_id);
      ~SctpStreamControl();

      DataChunkStatus deliver_chunk(const DataChunk &chunk);

    private:
      /**
       * After a new packet is received and delivered, the stream ssn may have
       * incremented such that a previously out of order packet can now be
       * delivered.
       *
       * This function delivers all packets in the reassembly queue that can now
       * be processed, and updates m_next_ssn to be the next expected SSN after
       * these packets have been delivered.
       */
      void deliver_outstanding();

      SctpAssociationControlBase &m_association;
      SctpStreamId m_this_stream_id;

      std::uint16_t m_next_ssn;
      using ReassemblyQueue = std::priority_queue< SctpDeliveredPacket*, std::vector<SctpDeliveredPacket*>, SctpComparePacketSsn >;
      ReassemblyQueue m_reassembly_queue;
    };

    class SctpAssociationControlBase {
    public:
      SctpAssociationControlBase(boost::asio::io_service &svc,
                                 const SctpHeader &hdr, const StateCookieData &cookie);

      virtual ~SctpAssociationControlBase();

      void cancel();

      std::uint32_t remote_verification_tag() const;
      std::uint32_t local_verification_tag() const;

      DataChunkStatus deliver_chunk(const DataChunk &chunk);
      void send_sack_if_necessary(SctpPacketBuilder &builder);

      template<typename RecvMsgHandler>
      void async_recv_msg(RecvMsgHandler completion) {
        boost::unique_lock l(m_transmission_mutex);
        if ( m_delivery_queue.empty() ) {
          m_readers.emplace_back(std::move(completion));
        } else {
          std::shared_ptr<SctpDeliveredPacket> pkt_ptr(m_delivery_queue.front().release());
          m_delivery_queue.pop_front();
          manager()->service().post([ pkt_ptr, completion{std::move(completion)} ] () {
              completion(boost::system::error_code(), *pkt_ptr);
            });
        }
      }

    protected:
      virtual std::shared_ptr<SctpManagerBase> manager() const =0;
      virtual std::shared_ptr<SctpAssociationControlBase> base_shared_from_this() =0;

      boost::mutex m_configuration_mutex;
      boost::mutex m_transmission_mutex;

    private:
      void start_sack_timer();
      void force_send_sack(boost::system::error_code ec);
      void send_sack(SctpPacketBuilder &pkt);

      SctpStreamControl &get_stream(SctpStreamId s);

      /**
       * Place the given packet immediately on the delivery queue, or deliver it
       * directly to a waiting reader.
       *
       * m_transmission_mutex must be held
       */
      void deliver_immediately(SctpDeliveredPacket *pkt);

      /**
       * Called by SctpStreamControl to notify us that this packet will be
       * stored.
       *
       * This decreases our window credit by the size of the packet.
       *
       * m_transmission_mutex must be held
       *
       * @returns true if the packet ought to be queued, or false if the packet should be dropped
       */
      bool will_store_packet(const SctpDeliveredPacket &pkt);

      /**
       * Called by SctpStreamControl to notify us that a previously stored
       * packet will be delivered.
       *
       * This increases the window credit by the size of the packet.
       *
       * m_transmission_mutex must be held
       */
      void will_deliver_stored_packet(const SctpDeliveredPacket &pkt);

      SctpPort m_source_port, m_destination_port;
      std::uint32_t m_remote_verification_tag, m_local_verification_tag;
      std::uint32_t m_cum_remote_tsn, m_highest_remote_tsn, m_local_tsn;
      std::vector<boost::asio::ip::address> m_addresses;

      std::uint32_t m_local_rwnd, m_remote_rwnd;
      std::uint16_t m_num_inbound, m_num_outbound;

      // SACK information

      /**
       * How long to delay an SACK
       */
      boost::posix_time::time_duration m_sack_debounce_interval;

      /**
       * Whether an SACK should be sent immediately
       */
      bool m_sack_required;

      /**
       * The number of packets received since the last SACK
       */
      std::uint8_t m_pkts_received;

      /**
       * TSNs we have received that are after m_cum_remote_tsn
       */
      util::fixed_array< std::pair<std::uint32_t, std::uint32_t>, 32> m_gap_tsns;
      /**
       * TSNs we received again
       */
      util::fixed_array< std::uint32_t, 64 > m_dup_tsns;

      boost::asio::deadline_timer m_sack_timer;
      SctpPacketBuilder m_sack_packet;

      // Streams

      /**
       * Information on each stream we have encountered thus far
       */
      std::unordered_map<SctpStreamId, SctpStreamControl > m_streams;

      // Read queue

      /**
       * The set of packets ready to be delivered
       */
      std::list< std::unique_ptr<SctpDeliveredPacket> > m_delivery_queue;

      /**
       * The listener callbacks waiting on a new packet
       */
      std::list< std::function<void (boost::system::error_code, const SctpDeliveredPacket &)> > m_readers;

      friend class SctpStreamControl;
    };

    template<typename Socket>
    class SctpAssociationControl : public SctpAssociationControlBase,
                                   public std::enable_shared_from_this< SctpAssociationControl<Socket> > {
    public:
      SctpAssociationControl(SctpManager<Socket> &mgr,
                             const SctpHeader &hdr, const StateCookieData &cookie)
        : SctpAssociationControlBase(mgr.service(), hdr, cookie),
          m_manager(mgr.shared_from_this())
      {
      }

      virtual ~SctpAssociationControl() {
      }

    protected:
      virtual std::shared_ptr<SctpManagerBase> manager() const override { return m_manager; }
      virtual std::shared_ptr<SctpAssociationControlBase> base_shared_from_this() override { return this->shared_from_this(); }

    private:
      std::shared_ptr< SctpManager<Socket> > m_manager;

    };

    template<typename Socket>
    class SctpManager : public std::enable_shared_from_this< SctpManager<Socket> >,
                        public SctpManagerBase {
    public:
      using acceptor_type = SctpAcceptor<Socket>;
      using socket_type = SctpAssociation<Socket>;
      using executor_type = typename Socket::executor_type;

      SctpManager(Socket &s, std::size_t max_size = 8 * 1024)
        : SctpManagerBase(s.service(), max_size), m_executor(s.get_executor()), m_socket(s) {
      }

      ~SctpManager() {
        this->stop();
      }

      virtual boost::asio::io_service &service() { return m_socket.service(); }

      void stop() {
        boost::unique_lock socket_l(m_socket_mutex);
        m_socket.cancel(); // Cancel all operations on this socket

        SctpManagerBase::stop();
      }

      void push_datagram(const boost::asio::const_buffer &datagram);

      inline executor_type &get_executor() const { return m_executor; }

    private:
      virtual void do_receive_next() override {
        m_socket.async_receive_from(boost::asio::buffer(m_incoming_packet), m_incoming_source,
                                    boost::bind(&SctpManagerBase::on_recv_packet, this->shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
      }

      virtual void do_send(boost::asio::const_buffer b) {
        m_socket.async_send(b, boost::bind(&SctpManagerBase::on_packet_sent, this->shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
      }

      virtual std::shared_ptr<SctpManagerBase> shared_base_from_this() override {
        return this->shared_from_this();
      }

      virtual std::weak_ptr<SctpManagerBase> weak_base_from_this() override {
        return this->weak_from_this();
      }

      virtual std::shared_ptr<SctpAssociationControlBase> new_association(const SctpHeader &hdr,
                                                                          const StateCookieData &d) {
        return std::make_shared< SctpAssociationControl<Socket> >(*this, hdr, d);
      }

      executor_type &m_executor;
      Socket &m_socket;

      friend class SctpAcceptor<Socket>;
      friend class SctpAssociationControl<Socket>;
    };

    template<typename Socket>
    class SctpAcceptorControl : public ISctpAcceptorControl,
                                public std::enable_shared_from_this< SctpAcceptorControl<Socket> > {
    public:
      using executor_type = typename Socket::executor_type;

      SctpAcceptorControl(SctpManager<Socket> &manager)
        : m_manager(manager.shared_from_this()) {
      }

      virtual void cancelled() override {
        // TODO
      }

      executor_type &get_executor() { return m_manager.get_executor(); }

      template<typename MoveHandler>
      void async_accept(MoveHandler on_accept) {
        if ( !is_bound_to_port() ) {
          boost::system::error_code ec;
          bind_port(0, ec);
          if ( ec ) return;
        }

        auto port(m_manager->get_port(m_port));
        if ( !port ) {
          m_manager->service().post([ on_accept ] () {
              on_accept(boost::system::error_code(ENOMEM, boost::system::generic_category()),
                        SctpAssociation<Socket>());
            });
          return;
        }

        port->async_accept([on_accept] (boost::system::error_code ec,
                                        std::shared_ptr<SctpAssociationControlBase> assoc) {
                             std::shared_ptr< SctpAssociationControl<Socket> > our_assoc;
                             if ( ec )
                               on_accept(ec, SctpAssociation<Socket>());
                             else {
                               our_assoc = std::dynamic_pointer_cast< SctpAssociationControl<Socket> >(assoc);
                               if ( our_assoc )
                                 on_accept(ec, SctpAssociation<Socket>(our_assoc));
                               else
                                 on_accept(boost::system::error_code(ENOMEM, boost::system::generic_category()), SctpAssociation<Socket>());
                             }
                           });
      }

      void bind_port(SctpPort port, boost::system::error_code &ec) {
        if ( is_bound_to_port() ) {
          ec = boost::system::error_code(EINVAL, boost::system::generic_category());
        } else if ( is_bound_to_addresses() ) {
          ec = boost::system::error_code(EINVAL, boost::system::generic_category());
        } else {
          if ( port == 0 ) {
            auto chosen_port(m_manager->choose_arbitrary_port());
            if ( chosen_port.first == 0 ) {
              ec = boost::system::error_code(EADDRINUSE, boost::system::generic_category());
              return;
            } else if ( !chosen_port.second ) {
              ec = boost::system::error_code(ENOMEM, boost::system::generic_category());
              return;
            } else {
              m_port = chosen_port.first;
              m_open_port = chosen_port.second;
            }
          } else {
            m_port = port;
            auto open_port(m_manager->get_port(port));
            if ( !open_port ) {
              ec = boost::system::error_code(ENOMEM, boost::system::generic_category());
              return;
            }
            m_open_port = open_port;
          }

          assert(m_open_port);
          m_open_port->bind(this->shared_from_this(), ec);
        }
      }

      void bind(const boost::asio::ip::address &ep, boost::system::error_code &ec) {
        if ( !is_bound_to_port() ) {
          bind_port(0, ec);
          if ( ec ) return;
        }

        m_addresses.insert(ep);
      }

      void listen(std::size_t backlog, boost::system::error_code &ec) {
        if ( !is_bound_to_port() ) {
          bind_port(0, ec);
          if ( ec ) return;
        }
        m_open_port->listen(backlog, ec);
      }

      void close() {
        cancelled();
      }

    private:
      bool is_bound_to_port() const { return m_port != 0 && m_open_port; }
      bool is_bound_to_addresses() const { return !m_addresses.empty(); }

      std::shared_ptr< SctpManager<Socket> > m_manager;

      SctpPort m_port;
      std::shared_ptr<SctpOpenPort> m_open_port;
      std::set<boost::asio::ip::address> m_addresses;
      // m_secret_key
    };

    template<typename Socket>
    class SctpAcceptor {
    public:
      using protocol_type = SctpManager<Socket>;
      using executor_type = typename Socket::executor_type;

      SctpAcceptor(SctpManager<Socket> &manager)
        : m_control(std::make_shared< SctpAcceptorControl<Socket> >(manager)) {
      }
      SctpAcceptor(SctpAcceptor<Socket> &&other)
        : m_control(std::move(other.m_control)) {
      }

      ~SctpAcceptor() {
        close();
      }

      template<typename MoveHandler>
      void async_accept(const MoveHandler &on_accept) {
        m_control->async_accept(on_accept);
      }

      void cancel() {
        if ( m_control )
          m_control->cancelled();
      };
      void close() {
        if ( m_control )
          m_control->close();
      };

      executor_type &get_executor() { return m_control->get_executor(); }

      void bind_port(SctpPort port, boost::system::error_code &ec) {
        m_control->bind_port(port, ec);
      };
      void bind(const boost::asio::ip::address &ep, boost::system::error_code &ec) {
        m_control->bind(ep, ec);
      };

      void listen(std::size_t backlog, boost::system::error_code &ec) {
        m_control->listen(backlog, ec);
      }
      void listen(std::size_t backlog) {
        boost::system::error_code ec;
        listen(backlog, ec);
        if ( ec ) throw ec;
      }

    private:
      std::shared_ptr< SctpAcceptorControl<Socket> > m_control;
    };

    template<typename Socket>
    class SctpAssociation {
    public:
      using protocol_type = SctpManager<Socket>;
      using executor_type = typename Socket::executor_type;

      inline SctpAssociation() { }

      template<typename RecvMsgHandler>
      void async_recv_msg(RecvMsgHandler completion) {
        if ( !m_association_control ) {
          completion(boost::system::error_code(EINVAL, boost::system::generic_category()), SctpDeliveredPacket());
        } else {
          m_association_control->async_recv_msg(std::move(completion));
        }
      }

    private:
      inline SctpAssociation(std::shared_ptr< SctpAssociationControl<Socket> > socket)
        : m_association_control(socket) {
      }

      std::shared_ptr< SctpAssociationControl<Socket> > m_association_control;

      friend class SctpOpenPort;
      friend class SctpAcceptorControl<Socket>;
    };
  }
}

#endif
