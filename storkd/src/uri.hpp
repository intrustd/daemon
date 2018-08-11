#ifndef __stork_uri_HPP__
#define __stork_uri_HPP__

#include <string>
#include <functional>
#include <boost/asio.hpp>
#include <uriparser/Uri.h>

namespace stork {
  namespace uri {
    enum error_code_t {
      success = 0,
      invalid_source = 1,
      not_found = 2,
      unavailable = 3,
      permission_denied = 4,
      unknown_scheme = 5,
      missing_port = 6
    };

    // TODO Use std::error_code
    class ErrorCode {
    public:
      inline ErrorCode() : m_code(success) {};
      inline ErrorCode(error_code_t e) : m_code(e) {};

      inline operator bool() const { return m_code == success; }

      inline error_code_t code() const { return m_code; }

      const char *description() const;

    private:
      error_code_t m_code;
    };

    class Uri;

    class UriPathIterator {
    public:
      inline operator bool() const { return m_cur_segment; }

      inline bool operator==(const UriPathIterator &b) const {
        return m_cur_segment == b.m_cur_segment;
      }

      inline UriPathIterator &operator++() {
        if ( m_cur_segment )
          m_cur_segment = m_cur_segment->next;
        return *this;
      }

      inline const UriTextRangeA operator*() const {
        return m_cur_segment->text;
      }

    private:
      inline UriPathIterator()
        : m_cur_segment(NULL) {
      }
      inline UriPathIterator(const UriUriA &parsed_uri)
        : m_cur_segment(parsed_uri.pathHead) {
      }

      friend class Uri;

      UriPathSegmentA *m_cur_segment;
    };

    class Uri {
    public:
      inline Uri(const Uri &uri)
        : m_uri(uri.m_uri), m_is_valid(false) {
        validate();
      }
      inline Uri() : m_is_valid(false) {};
      inline Uri(const std::string &uri_data)
        : m_uri(uri_data), m_is_valid(false) {
        validate();
      }
      Uri(Uri &&u) noexcept; // Move constructor
      ~Uri();

      inline bool is_valid() const { return m_is_valid; }
      inline bool is_absolute() const { return is_valid() && m_parsed_uri.absolutePath == URI_TRUE; }

      inline bool operator==(const Uri &b) const {
        if ( is_valid() && b.is_valid() ) {
          return uriEqualsUriA(&m_parsed_uri, &b.m_parsed_uri) == URI_TRUE;
        } else
          return is_valid() == b.is_valid();
      }

      inline const std::string &raw() const { return m_uri; }
      inline const std::string canonical() const { return m_uri; } // TODO actually canonicalize
      std::string host() const;

      std::uint16_t port() const;
      std::string port_text() const;
      bool has_port() const;

      const Uri &operator=(const std::string &s);
      const Uri &operator=(const Uri& u);
      bool has_scheme(const char *scheme) const;

      void reset();

      UriPathIterator begin() const;
      UriPathIterator end() const;

    private:
      void validate();

      std::string m_uri;

      bool m_is_valid;
      UriUriA m_parsed_uri;
    };

    class IUriSource {
    public:
      virtual ~IUriSource();

      virtual void async_fetch_some(boost::asio::mutable_buffer b,
                                    std::function<void(ErrorCode, std::size_t)> cb) =0;
    };

    class UriSource {
    public:
      UriSource(boost::asio::io_service &svc, const Uri &uri);
      ~UriSource();

      inline bool is_valid() const { return m_source.get(); }

      IUriSource &source() { return *(m_source.get()); }

    private:
      boost::asio::io_service &m_service;
      Uri m_uri;

      std::shared_ptr<IUriSource> m_source;
    };

    class UriSaver {
    public:
      UriSaver(std::ostream &output, std::unique_ptr<UriSource> src, std::size_t chunk_size=4096);
      ~UriSaver();

      void async_save(std::function<void(ErrorCode)> cb);

    private:
      std::ostream &m_output;

      std::unique_ptr<UriSource> m_source;

      std::vector<std::uint8_t> m_buffer;
    };

    class UriFetcher {
    public:
      UriFetcher(std::unique_ptr<UriSource> src, std::size_t max_size=0);
      ~UriFetcher();

      inline bool has_max_size() const { return m_max_size != 0; }
      inline UriSource &source() { return *m_source; }

      void async_fetch(std::function<void(ErrorCode, const std::string&)> cb);

    private:
      std::unique_ptr<UriSource> m_source;

      std::size_t m_max_size;
      std::string m_buffer;
    };
  }
}

// inline std::ostream &operator<<(std::basic_ostream &out, const stork::uri::Uri &uri) {
//   out << uri.raw();
//   return out;
// }

#endif
