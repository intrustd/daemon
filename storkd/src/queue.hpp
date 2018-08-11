#ifndef __stork_util_queue_HPP__
#define __stork_util_queue_HPP__

#include <boost/asio.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/log/trivial.hpp>

#include <functional>
#include <deque>

namespace stork {
  namespace util {
    class queue {
    public:
      inline queue(boost::asio::io_service &svc)
        : m_is_working(false), m_service(svc) {
      };
      inline ~queue() {};

      struct reason {
      public:
        inline bool will_not_run() const { return !m_will_run; }
        inline bool normal() const { return m_will_run; }

      private:
        inline reason(bool will_run = true) : m_will_run(will_run) { }

        inline bool run_remaining() const { return m_will_run; }

        friend class queue;

        bool m_will_run;
      };

      template<typename Handler>
      void dispatch(Handler &&h) {
        boost::unique_lock l(m_mutex);
        if ( m_work.empty() && !m_is_working ) {
          m_is_working = true;
          m_service.post([h{std::move(h)}] () mutable { h(reason()); });
        } else {
          m_work.push_back(std::move(h));
        }
      };

      template<typename Handler>
      void post(Handler &&h) {
        m_service.post([h{std::move(h)}, this] () {
            BOOST_LOG_TRIVIAL(debug) << "Dispatching handler";
            this->dispatch(std::move(h));
          });
      }

      inline void async_restart() {
        boost::unique_lock l(m_mutex);
        if ( m_is_working ) {
          m_is_working = false;
          if ( !m_work.empty() ) {
            auto f(std::move(m_work.front()));
            m_work.pop_front();
            m_is_working = true;
            m_service.post([f{std::move(f)}] () { f(reason()); });
          }
        }
      }

      inline void suspend() {
        boost::unique_lock l(m_mutex);
        m_is_working = true;
      }

      inline void purge_all() {
        boost::unique_lock l(m_mutex);
        if ( m_is_working ) {
          std::deque< std::function<void(reason)> > new_work;
          new_work.swap(m_work);

          for ( const auto &fn : new_work ) {
            fn(reason(false));
          }

          m_is_working = false;
        }
      }

    private:
      boost::mutex m_mutex;
      bool m_is_working;
      std::deque< std::function<void(reason)> > m_work;

      boost::asio::io_service &m_service;
    };
  }
}

#endif
