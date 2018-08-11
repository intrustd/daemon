#ifndef __stork_peer_push_pull_HPP__
#define __stork_peer_push_pull_HPP__

#include <boost/asio.hpp>
#include <functional>
#include <queue>

namespace stork {
  namespace peer {
    class IRTCChannel {
    public:
      virtual ~IRTCChannel();

      virtual void accept_datagram(const boost::asio::ip::udp::endpoint &ep,
                                   const boost::asio::const_buffer &buffer,
                                   std::function<void()> completion) =0;
    };

    class IRTCSink {
    public:
      virtual ~IRTCSink();

      virtual void send_datagram(const boost::asio::const_buffer &buffer,
                                 std::function<void(boost::system::error_code, std::size_t)> completion) =0;
    };

    /**
     * Provides a class that converts a push based socket interface
     * into a pull based one. Internally, it uses a buffer of the
     * supplied length. Additional pushes after this number are
     * silently dropped.
     *
     * Implements IRTCChannel
     *
     * Writes are sent via the supplied IRTCSink
     */
    class PushPullAdaptor : public IRTCChannel, public std::enable_shared_from_this<PushPullAdaptor> {
    public:
      PushPullAdaptor(boost::asio::io_service &svc, std::size_t n = 8);
      virtual ~PushPullAdaptor();

      void set_sink(IRTCSink *sink);
      void stop_sink();

      virtual void accept_datagram(const boost::asio::ip::udp::endpoint &ep,
                                   const boost:asio::const_buffer &buffer,
                                   std::function<void()> completion);

      template<typename Completion>
      void async_receive_from(const boost::asio::mutable_buffer &mb,
                              boost::asio::ip::udp::endpoint &ep,
                              Completion completion) {
        // First, check if we have waits. If so, then add to the end
        // of the wait queue
        //
        // Otherwise, check if we have packets waiting. If so, then
        // dispatch immediately.
        //
        // Otherwise, if both are empty, add to the wait queue
        boost::upgrade_lock fifo_l(m_fifo_mutex);
        boost::upgrade_lock wait_l(m_wait_mutex);

        if ( !m_waits.empty() ) {
          if  ( m_waits < m_max_fifo_size ) {
            boost::upgrade_to_unique_lock wait_write_l(wait_l);
            // Add to wait queue
            m_waits.push(std::make_unique< PendingRead<Completion> >(ep, mb, std::move(completion)));
          } else {
            // No more space in queue. Call immediately with error
            m_service.post(boost::bind(completion, boost::system::make_error_code(EBUSY, boost::system::generic_category()), 0));
          }
        } else if ( !m_fifo.empty() ) {
          wait_l.unlock();

          // We have packets waiting, so we can dispatch immediately
          boost::upgrade_to_unique_lock fifo_write(fifo_l); // TODO deadlocks?
          PushedWrite &pending(m_fifo.front());
          // Copy buffer
          std::size_t bytes_copied(copy_buffer(mb, pending.buffer()));
          ep = pending.from();

          m_service.post(boost::bind(completion, boost::system::error_code(), bytes_copied));
          m_fifo.pop_front();
        } else {
          boost::upgrade_to_unique_lock wait_write_l(wait_l);
          // Add to wait queue
          m_waits.push(std::make_unique< PendingRead<Completion> >(ep, mb, std::move(completion)));
        }
      }

      void async_send_to(const boost::asio::const_buffer &cb,
                         const boost::asio::ip::udp::endpoint &ep,
                         std::function<void(boost::system::error_code, std::size_t) completion);

    private:
      boost::asio::io_service &m_service;

      class PushedWrite {
      public:
        PushedWrite(const boost::asio::ip::udp::endpoint &ep,
                    const boost::asio::const_buffer &buffer,
                    std::function<void()> &&completion);

        inline const boost::asio::ip::udp::endpoint &from() const { return m_from; }
        inline const boost::asio::const_buffer &buffer() const { return m_buffer; }
        inline const std::function<void()> &on_complete() const { return m_on_complete; }

      private:
        boost::asio::ip::udp::endpoint m_from;
        boost::asio::const_buffer m_buffer;
        std::function<void()> m_on_complete;
      };

      class IPendingRead {
      public:
        IPendingRead(boost::asio::ip::udp::endpoint &ep,
                     const boost::asio::mutable_buffer &mb);

        virtual ~IPendingRead();
        virtual void operator() (boost::asio::io_service &svc,
                                 boost::system::error_code ec, std::size_t bytes_read) =0;

        void fulfill(const boost::asio::ip::udp::endpoint &from,
                     const boost::asio::const_buffer &data);

      protected:
        boost::asio::ip::udp::endpoint &m_endpoint;
        boost::asio::mutable_buffer m_buffer;
      };

      template<typename Completion>
      class PendingRead : public IPendingRead {
      public:
        PendingRead(boost::asio::ip::udp::endpoint &ep,
                    const boost::asio::mutable_buffer &mb,
                    Completion &&cb)
          : IPendingRead(ep, mb), m_completion(std::move(cb)) {
        }

        virtual ~PendingRead() { }

        virtual void operator() (boost::asio::io_service &svc, boost::system::error_code ec, std::size_t bytes_read) {
          svc.post(boost::bind(m_completion, ec, bytes_read));
        }

      private:
        Completion m_completion;
      };

      std::size_t m_max_fifo_size;

      boost::mutex m_fifo_mutex;
      std::queue<PushedWrite> m_fifo;

      boost::mutex m_wait_mutex;
      std::queue< std::unique_ptr<IPendingRead> > m_waits;

      boost::mutex m_sink_mutex;
      // TODO queue up sends, if there is no sink
      IRTCSink *m_sink;
    };
  }
}

#endif
