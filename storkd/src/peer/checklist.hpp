#ifndef __stork_peer_checklist_HPP__
#define __stork_peer_checklist_HPP__

#include <boost/iterator/filter_iterator.hpp>
#include <boost/log/trivial.hpp>

#include "../util/array.hpp"
#include "ice.hpp"

namespace stork {
  namespace peer {
    template<typename Pair, std::size_t N>
    class IceCheckList {
    private:
      class ValidPair {
      public:
        bool operator() (const Pair &p) const {
          return p.valid();
        }
      };

    public:
      using Pairs = std::array<Pair, N>;
      using iterator = boost::filter_iterator< ValidPair, typename Pairs::iterator>;
      using size_type = typename Pairs::size_type;

      enum State {
        invalid,
        running,
        completed,
        failed
      };

      IceCheckList()
        : m_state(running), m_size(0) {
      }

      State state() const { return m_state; }

      void add_candidate_pair(const typename Pair::remote_type &r,
                              const typename Pair::local_type &l) {
        Pair p(r, l);
        if ( p.well_formed() ) {

          auto found(std::find_if(begin(), end(),
                                  [&p] ( const Pair &in_checklist ) {
                                    return in_checklist.is_redundant_with(p);
                                  }));

          if ( found == end() ) {
            BOOST_LOG_TRIVIAL(debug) << "Adding candidate pair";
            // This pair is okay to insert
            auto space(find_empty());
            if ( space == m_pairs.end() ) {
              space = prune(p.priority());
            }

            if ( space == m_pairs.end() ) {
              BOOST_LOG_TRIVIAL(error) << "No space to insert candidate pair";
              return;
            }

            p.start_wait(); // Transition to waiting state
            *space = p;
            insert_waiting_pair(space);

            m_size ++;
          } else {
            // This pair is redundant
            //
            // According to step 4A of Section 11 of
            // https://tools.ietf.org/html/draft-ietf-ice-trickle-21,
            //
            // if the remote candidate is peer reflexive, we discard
            // this pair, but replace the priority of the existing
            // pair

            if ( ice_candidate(*r).type() == IceCandidate::prflx ) {
              reprioritize_pair(found.base(), p.priority());
            }
          }
        } else
          BOOST_LOG_TRIVIAL(debug) << "Skip add candidate pair";
      }

      iterator begin() {
        return boost::make_filter_iterator(ValidPair(), m_pairs.begin(), m_pairs.end());
      }
      iterator end() { return begin().end(); }

      size_type size() const { return m_size; }

      bool has_failed() const { return m_state == State::failed; }
      bool has_succeeded() const { return m_state == State::completed; }

      void update_state() {
        // If we have any nominated candidate, then we're done
        auto nominated(find_nominated());
        if ( nominated != end() ) {
          m_state = State::completed;
        } else {
          // Otherwise, prune our pairs, to remove failed ones
          prune(0);

          // If there are still pairs left, then we're running
          if ( size() > 0 ) {
            m_state = State::running;
          } else
            m_state = State::failed;
        }
      }

      iterator find_candidate_pair(const boost::asio::ip::udp::endpoint &remote,
                                   const boost::asio::ip::udp::endpoint &local) {
        return std::find_if(begin(), end(),
                            [&remote, &local] ( const Pair &p ) {
                              return
                                p.remote_candidate().addr() == remote.address() &&
                                p.remote_candidate().port() == remote.port() &&
                                p.local_candidate().addr() == local.address() &&
                                p.local_candidate().port() == local.port();
                            });
      }

      iterator find_check_in_progress(const StunTransactionId &tx_id) {
        return std::find_if(begin(), end(),
                            [ &tx_id ] ( const Pair &p ) {
                              return p.is_in_progress() &&
                                p.check_tx_id() == tx_id;
                            });
      }

      inline bool has_waiting() const { return !m_sorted_waiting_pairs.empty(); }
      Pair &pop_waiting() {
        if ( has_waiting() ) {
          auto &r(*m_sorted_waiting_pairs.back());
          m_sorted_waiting_pairs.pop_back();
          return r;
        } else
          return *begin();
      }

      iterator find_nominated() {
        return std::find_if(begin(), end(),
                            [] (const Pair &p) {
                              return p.nominated();
                            });
      }

    private:
      typename Pairs::iterator prune(std::uint64_t priority) {
        for ( Pair &p : *this ) {
          if ( p.failed() ) {
            p.invalidate();
            m_size--;
          }
        }

        auto empty(find_empty());

        if ( find_empty() == m_pairs.end() &&
             !m_sorted_waiting_pairs.empty() &&
             m_sorted_waiting_pairs.front()->priority() < priority ) {

          empty = m_sorted_waiting_pairs.front();
          // If there is still no space, then evict the waiting pair with lowest priority
          empty->invalidate(); // Free up the lowest priority
          m_size --;

          std::copy(m_sorted_waiting_pairs.begin() + 1, m_sorted_waiting_pairs.end(), m_sorted_waiting_pairs.begin());
          m_sorted_waiting_pairs.resize(m_sorted_waiting_pairs.size() - 1);
        }

        return empty;
      }

      typename Pairs::iterator find_empty() {
        return std::find_if(m_pairs.begin(), m_pairs.end(), [] ( const Pair &p ) { return p.invalid(); });
      }

      static bool compare_priorities(const typename Pairs::iterator &a, const typename Pairs::iterator &b) {
        return a->priority() < b->priority();
      }

      static bool compare_priority_static(const typename Pairs::iterator &a, std::uint64_t p) {
        return a->priority() < p;
      }

      void reprioritize_pair(typename Pairs::iterator pair_ptr, std::uint64_t new_priority) {
        if ( pair_ptr->priority() != new_priority ) {
          auto old_pos(std::lower_bound(m_sorted_waiting_pairs.begin(), m_sorted_waiting_pairs.end(), pair_ptr->priority(), compare_priority_static));
          auto new_pos(std::lower_bound(m_sorted_waiting_pairs.begin(), m_sorted_waiting_pairs.end(), new_priority, compare_priority_static));

          pair_ptr->reprioritize(new_priority);

          if ( old_pos != m_sorted_waiting_pairs.end() ) {
            if ( old_pos < new_pos ) {
              std::copy(old_pos + 1, new_pos, old_pos);
              *new_pos = pair_ptr;
            } else {
              std::copy_backward(new_pos, old_pos, old_pos - 1);
              *new_pos = pair_ptr;
            }
          }
        }
      }

      void insert_waiting_pair(typename Pairs::iterator pair_ptr) {
        auto insert_before(std::lower_bound(m_sorted_waiting_pairs.begin(), m_sorted_waiting_pairs.end(), pair_ptr, compare_priorities));
        if ( insert_before == m_sorted_waiting_pairs.end() )
          m_sorted_waiting_pairs.push_back(pair_ptr);
        else {
          std::copy(insert_before, m_sorted_waiting_pairs.end(), insert_before + 1);
          *insert_before = pair_ptr;
        }
      }

      Pairs m_pairs;
      util::fixed_array< typename Pairs::iterator, N > m_sorted_waiting_pairs;
      State m_state;
      size_type m_size;
    };
  }
}

#endif
