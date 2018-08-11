#include "manager.hpp"

namespace stork {
  namespace sctp {
    SctpOpenPort::SctpOpenPort(std::shared_ptr<SctpManagerBase> base)
      : m_manager(base), m_listen_queue_length(0) {
    }

    SctpOpenPort::~SctpOpenPort() {
      // We should warn if there are listeners
      boost::unique_lock port_l(m_port_mutex);
      if ( !m_listeners.empty() )
        BOOST_LOG_TRIVIAL(warning) << "Destroying SctpOpenPort with listeners";
      cancel();
    }

    void SctpOpenPort::cancel() {
      boost::system::error_code ec(ECANCELED, boost::system::generic_category());
      if ( !m_listeners.empty() ) {
        for ( auto listener(m_listeners.front());
              !m_listeners.empty();
              m_listeners.pop(), listener = m_listeners.front() ) {
          m_manager->service().post(boost::bind(listener, ec, nullptr));
        }
      }
    }

    void SctpOpenPort::async_accept(ListenerCallback cb) {
      boost::unique_lock l(m_port_mutex);
      BOOST_LOG_TRIVIAL(debug) << "ASYNC ACCEPT called";

      if ( _is_listening() ) {
        if ( !m_listen_queue.empty() ) {
          BOOST_LOG_TRIVIAL(debug) << "ASYNC ACCEPT returns immediately";
          auto assoc(m_listen_queue.front());
          m_listen_queue.pop_front();

          m_manager->service().post([cb, assoc]() {
              cb(boost::system::error_code(), assoc);
            });
        } else {
          BOOST_LOG_TRIVIAL(debug) << "ASYNC ACCEPT enters waiting queue";
          m_listeners.push(cb);
        }
      } else
        BOOST_LOG_TRIVIAL(debug) << "ASYNC ACCEPT fails because not listening";
    }

    SctpOpenPort::AssociationResult
    SctpOpenPort::receive_association(const boost::asio::ip::address &ip,
                                      const SctpHeader &hdr,
                                      const StateCookieData &d) {
      boost::unique_lock l(m_port_mutex);

      if ( _is_listening() ) {
        auto existing(m_associations.find(ip));

        if ( existing == m_associations.end() ) {
          auto assoc(m_manager->new_association(hdr, d));
          if ( !assoc )
            return association_error_no_mem;

          m_associations.insert(std::make_pair(ip, assoc));

          if ( m_listeners.empty() ) {
            BOOST_LOG_TRIVIAL(debug) << "Nothing listening, so pushing association onto queue";
            if ( m_listen_queue.size() >= m_listen_queue_length )
              return association_rejected;
            else {
              m_listen_queue.push_back(assoc);
              return association_created;
            }
          } else {
            BOOST_LOG_TRIVIAL(debug) << "Sending association to listener";
            ListenerCallback cb(std::move(m_listeners.front()));
            m_listeners.pop();

            m_manager->service().post([ cb{std::move(cb)}, assoc ] () {
                cb(boost::system::error_code(), assoc);
              });

            return association_created;
          }
        } else
          return association_already_exists;
      } else
        return association_rejected;
    }

    bool SctpOpenPort::is_listening() {
      boost::unique_lock l(m_port_mutex);
      return _is_listening();
    }

    void SctpOpenPort::listen(std::size_t backlog, boost::system::error_code &ec) {
      boost::unique_lock l(m_port_mutex);
      backlog = std::min<std::size_t>(64, std::max<std::size_t>(backlog, m_listen_queue_length));

      // TODO offer way to shrink backlog
      m_listen_queue_length = backlog;
    }

    void SctpOpenPort::bind(std::shared_ptr<ISctpAcceptorControl> a,
                            boost::system::error_code &ec) {
      boost::unique_lock l(m_port_mutex);
      m_acceptors.insert(a);
    }
  }
}
