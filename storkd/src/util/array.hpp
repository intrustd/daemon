#ifndef __stork_util_array_HPP__
#define __stork_util_array_HPP__

namespace stork {
  namespace util {
    template<typename T, std::size_t N>
    class fixed_array : public std::array<T, N> {
    public:
      using value_type = typename std::array<T, N>::value_type;
      using size_type = typename std::array<T, N>::size_type;
      using difference_type = typename std::array<T, N>::difference_type;
      using reference = typename std::array<T, N>::reference;
      using const_reference = typename std::array<T, N>::const_reference;
      using pointer = typename std::array<T, N>::pointer;
      using const_pointer = typename std::array<T, N>::const_pointer;
      using iterator = typename std::array<T, N>::iterator;
      using const_iterator = typename std::array<T, N>::const_iterator;
      using reverse_iterator = typename std::array<T, N>::reverse_iterator;
      using const_reverse_iterator = typename std::array<T, N>::const_reverse_iterator;

      static constexpr std::size_t max_size = N;

      fixed_array() : m_size(0) { };
      fixed_array(const T &x, size_type n=0)
        : m_size(std::min(n, N)) {
        this->fill(x);
      }

      void pop_back() {
        if ( m_size > 0 )
          m_size --;
      }

      inline size_type size() const { return std::min(m_size, N); }
      inline bool has_space() const { return size() < N; }

      fixed_array<T, N> &operator=(const fixed_array<T, N> &a) {
        m_size = a.size();

        std::copy(a.begin(), a.begin() + a.size(), this->begin());
        return *this;
      }

      reference at( size_type pos ) {
        if ( pos >= m_size )
          throw std::out_of_range("Access beyond bounds of array");
        return std::array<T, N>::at(pos);
      };

      const_reference at(size_type pos) const {
        if ( pos >= m_size )
          throw std::out_of_range("Access beyound bounds of array");
        throw std::array<T, N>::at(pos);
      }

      void resize(std::size_t new_size) {
        new_size = std::min(N, new_size);
        if ( new_size < size() ) {
          for ( std::size_t i = new_size; i < size(); ++i )
            (std::array<T, N>::at(i)).~T();
        } else if ( new_size > size() ) {
          for ( std::size_t i = size(); i < new_size; ++i )
            new (&(std::array<T, N>::at(i))) T();
        }
        m_size = new_size;
      }
      void clear() { resize(0); }

      reference operator[]( size_type pos ) { return at(pos); }
      const_reference operator[]( size_type pos) const { return at(pos); }

      template<typename Cond>
      void remove_if(Cond c) {
        auto new_end(std::remove_if(this->begin(), this->end(), c));
        m_size = std::distance(this->begin(), new_end);
      }

      reference back() {
        auto tmp = this->begin();
        tmp += size();
        tmp --;
        return *tmp;
      }
      const_reference back() const {
        auto tmp = this->cbegin();
        tmp += size();
        tmp --;
        return *tmp;
      }

      iterator end() {
        return this->begin() + size();
      }
      const_iterator end() const {
        return cend();
      }
      const_iterator cend() const {
        return this->cbegin() + size();
      }
      reverse_iterator rbegin() {
        auto r(std::array<T,N>::rbegin());
        std::advance(r, N - size());
        return r;
      }
      const_reverse_iterator crbegin() const {
        auto r(std::array<T,N>::crbegin());
        std::advance(r, N - size());
        return r;
      }

      bool empty() const { return m_size == 0; }

      void swap(fixed_array<T, N> &a) noexcept {
        std::swap(m_size, a.m_size);
        std::array<T, N>::swap(a);
      }

      void push_back(const T& n) {
        if ( has_space() ) {
          std::array<T,N>::at(m_size) = n;
          m_size++;
        }
      }
    private:
      size_type m_size;
    };
  }
}

#endif
