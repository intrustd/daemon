#include <arpa/inet.h>

#include "proto.hpp"
#define DEFINE_RANDOM 1
#include "random.hpp"
#undef DEFINE_RANDOM

namespace stork {
  namespace util {
    random_string_class random_string;
    const char *random_string_class::chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz"
      "0123456789+/"; //!@#$%^&*()!?+|}{[]/=\\',.<>~`";
  }
  namespace proto {
    ProtoParseException::~ProtoParseException() {
    }

    const char *ProtoParseException::what() const noexcept {
      return m_what;
    }

    ProtoParser &ProtoParser::parseFixedLenString(const char *what, std::string &out, std::size_t len) {
      out.resize(len);
      if ( !m_stream.read(out.data(), len) )
        throw ProtoParseException(what);

      return *this;
    }

    ProtoParser &ProtoParser::parseVarLenString(const char *what, std::string &out) {
      std::uint32_t sz(0);
      parse<std::uint32_t>(what, sz);
      out.resize(sz);

      if ( !m_stream.read(out.data(), sz) )
        throw ProtoParseException(what);

      return *this;
    }

    ProtoBuilder &ProtoBuilder::interVarLenString(const std::string &s) {
      inter<std::uint32_t>(s.size());
      m_stream << s;
      return *this;
    }

    ProtoBuilder &ProtoBuilder::interFixedLenString(const std::string &s, std::size_t l, char fill) {
      if ( s.size() >= l ) {
        m_stream.write(s.c_str(), l);
      } else {
        m_stream.write(s.c_str(), l - s.size());

        for ( std::size_t i = 0; i < (l - s.size()); ++i )
          m_stream.put(fill);
      }

      return *this;
    }
  }
}
