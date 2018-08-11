#ifndef __stork_util_heap_HPP__
#define __stork_util_heap_HPP__

namespace stork {
  namespace util {
    template<typename RandomIterator, typename LessThan>
    void decrease_heap_key(RandomIterator begin, RandomIterator i,LessThan cmp) {
      for ( auto parent(i); parent != begin;
            i = parent ) {
        if ( cmp(*parent, *i) ) return;
        else {
          std::swap(*parent, *i);

          parent = begin;
          std::advance(parent, (std::distance(begin, parent) - 1) / 2);
        }
      }
    }
  }
}

#endif
