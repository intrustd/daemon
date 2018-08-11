#ifndef __stork_util_random_HPP__
#define __stork_util_random_HPP__

#include <cstring>
#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>

namespace stork {
  namespace util {
    class random_string_class {
    public:
      inline std::string operator() (std::size_t len) {
        std::size_t nchars = strlen(chars);
        boost::random::random_device rng;
        boost::random::uniform_int_distribution<> index_dist(0, nchars - 1);

        std::string r;
        r.resize(len);

        for ( std::size_t i = 0; i < len; i ++ ) {
          r[i] = chars[index_dist(rng)];
        }

        return std::move(r);
      };

    private:
      static const char *chars; // defined in proto.cpp
    };

#ifndef DEFINE_RANDOM
    extern random_string_class random_string;
#endif

    template<typename T>
    class random_iterator {
    public:
      random_iterator(const T *chrs, std::size_t char_count, std::size_t remaining)
        : m_chars(chrs), m_char_count(char_count), m_remaining(remaining),
          m_dist(0, m_char_count - 1) {
        next_char();
      }
      random_iterator(std::size_t remaining)
        : m_chars(nullptr), m_char_count(255), m_remaining(remaining) {
      }
      random_iterator(const random_iterator &i)
        : m_chars(i.m_chars), m_char_count(i.m_char_count),
          m_remaining(i.m_remaining), m_cur_char(i.m_cur_char), m_dist(i.m_dist) {
      }

      random_iterator()
        : m_chars(nullptr), m_char_count(0), m_remaining(0), m_cur_char(0) {
      }

      bool operator==(const random_iterator<T> &x) const {
        if ( x.m_chars && m_chars ) {
          return x.m_chars == m_chars && x.m_remaining == m_remaining &&
            x.m_cur_char == m_cur_char;
        } else if ( !x.m_chars ) {
          return m_remaining == 0;
        } else if ( !m_chars ) {
          return x.m_remaining == 0;
        } else
          return false;
      }

      bool operator!=(const random_iterator<T> &x) const {
        return !(*this == x);
      }

      T operator*() {
        return m_cur_char;
      }

      random_iterator &operator++() {
        return (*this)++;
      }

      random_iterator &operator++(int i) {
        if ( m_remaining > 0 ) {
          m_remaining--;
          next_char();
        }
        return *this;
      }

    private:
      void next_char() {
        if ( m_chars )
          m_cur_char = m_chars[m_dist(m_gen)];
        else
          m_cur_char = (char) m_dist(m_gen);
      }

      boost::random::random_device m_gen;

      const T *m_chars;
      std::size_t m_char_count, m_remaining;

      unsigned int m_cur_char;
      boost::random::uniform_int_distribution<std::size_t> m_dist;
    };
  }
}

namespace std {
  template<typename T>
  struct iterator_traits<stork::util::random_iterator<T>> {
    using value_type = T;
    using iterator_category = std::forward_iterator_tag;
  };
}

#endif
