#ifndef __stork_util_parse_utils_HPP__
#define __stork_util_parse_utils_HPP__

#include <boost/log/trivial.hpp>

namespace stork {
  inline bool names_equal(const char *name_start, const char *name_end, const char *exp) {
    int i = 0;
    for ( i = 0; exp[i] != '\0' && name_start != name_end; name_start ++, i ++ ) {
      if ( exp[i] != *name_start ) return false;
    }

    return name_start == name_end && exp[i] == '\0';
  }

  inline bool names_start_with(const char *name_start, const char *name_end, const char *pfx) {
    int i = 0;
    for ( i = 0; pfx[i] != '\0' && name_start != name_end; name_start ++, i ++ )
      if ( pfx[i] != *name_start ) return false;

    return pfx[i] == '\0';
  }

  template<typename InputIterator, typename OutputIterator>
  OutputIterator copy_max(InputIterator first, InputIterator end, OutputIterator dfirst, OutputIterator dend) {
    for ( ; first != end && dfirst != dend; first ++, dfirst ++ )
      *dfirst = *first;

    return dfirst;
  }

  inline std::uint8_t hex_value(char c) {
    if ( c >= '0' && c <= '9' ) return (c - '0');
    else if ( c >= 'A' && c <= 'F') return (c - 'A' + 10);
    else if ( c >= 'a' && c <= 'f') return (c - 'a' + 10);
    else return 0;
  }
}

#endif
