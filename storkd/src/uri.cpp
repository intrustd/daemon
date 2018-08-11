#include <sstream>
#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>

#include "uri.hpp"

namespace fs = boost::filesystem;

namespace stork {
  namespace uri {
    const char *ErrorCode::description() const {
      switch ( m_code ) {
      case success:
        return "Success";
      case invalid_source:
        return "Invalid source";
      case not_found:
        return "Not found";
      case unavailable:
        return "Unavailable";
      case permission_denied:
        return "Permission denied";
      case unknown_scheme:
        return "Unknown scheme";
      case missing_port:
        return "Missing port";
      default:
        return "Unknown error";
      }
    }

    Uri::Uri(Uri &&u) noexcept
      : m_uri(std::move(u.m_uri)),
        m_is_valid(u.m_is_valid),
        m_parsed_uri(u.m_parsed_uri)
    {
      u.m_is_valid = false;
    }

    Uri::~Uri() {
      reset();
    }

    void Uri::reset() {
      if ( m_is_valid ) {
        uriFreeUriMembersA(&m_parsed_uri);
        m_is_valid = false;
      }
    }

    void Uri::validate() {
      UriParserStateA state;

      reset();

      state.uri = &m_parsed_uri;
      if ( uriParseUriA(&state, m_uri.c_str()) == URI_SUCCESS ) {
        m_is_valid = true;
      } else
        uriFreeUriMembersA(&m_parsed_uri);
    }

    std::string Uri::host() const {
      if ( m_is_valid ) {
        std::string r(m_parsed_uri.hostText.first, m_parsed_uri.hostText.afterLast);
        return r;
      } else {
        return "";
      }
    }

    std::uint16_t Uri::port() const {
      if ( has_port() ) {
        std::stringstream s(port_text());
        std::uint16_t r;

        s >> r;

        return r;
      } else
        return 0;
    }

    std::string Uri::port_text() const {
      if ( has_port() ) {
        std::string r(m_parsed_uri.portText.first, m_parsed_uri.portText.afterLast);
        return r;
      } else
        return "";
    }

    bool Uri::has_port() const {
      return (m_is_valid && m_parsed_uri.portText.first && m_parsed_uri.portText.afterLast &&
              m_parsed_uri.portText.afterLast != m_parsed_uri.portText.first);
    }

    const Uri &Uri::operator=(const std::string &s) {
      reset();

      m_uri = s;
      validate();

      return *this;
    }

    const Uri &Uri::operator=(const Uri &u) {
      reset();

      (*this) = u.m_uri;

      return *this;
    }

    bool Uri::has_scheme(const char *scheme) const {
      if (m_is_valid) {
        std::size_t scheme_length = m_parsed_uri.scheme.afterLast - m_parsed_uri.scheme.first;

        if ( strlen(scheme) == scheme_length )
          return std::equal(m_parsed_uri.scheme.first, m_parsed_uri.scheme.afterLast, scheme);
        else
          return false;
      } else
        return false;
    }

    UriPathIterator Uri::begin() const {
      if ( m_is_valid )
        return UriPathIterator(m_parsed_uri);
      else
        return UriPathIterator();
    }

    UriPathIterator Uri::end() const {
      return UriPathIterator();
    }

    IUriSource::~IUriSource() {};

    class FileUriSource : public IUriSource {
    public:
      FileUriSource(boost::asio::io_service &svc, const Uri &uri)
        : m_service(svc) {
        if ( uri.is_absolute() )
          p = "/";
        else
          p = "./";

        for ( const UriTextRangeStructA &segment: uri ) {
          std::string segment_string(segment.first, segment.afterLast);
          p /= segment_string;
        }

        f.open(p.string(), std::fstream::in);
      }
      virtual ~FileUriSource() {};

      const fs::path& absolute_path() const { return p; }

      virtual void async_fetch_some(boost::asio::mutable_buffer b,
                                    std::function<void(ErrorCode, std::size_t)> cb) {
        BOOST_LOG_TRIVIAL(debug) << "Fetching from file " << p;

        if ( f.eof() )
          cb(success, 0);
        else if ( !f.is_open() )
          cb(not_found, 0);
        else {
          std::size_t buf_size = boost::asio::buffer_size(b);
          char *buf_data = boost::asio::buffer_cast<char*>(b);

          if ( f.read(buf_data, buf_size) ) {
            cb(success, f.gcount());
          } else {
            if ( f.eof() )
              cb(success, f.gcount());
            else
              cb(unavailable, 0);
          }
        }
      }

    private:
      boost::asio::io_service &m_service;
      fs::path p;
      std::fstream f;
    };

    UriSource::UriSource(boost::asio::io_service &svc, const Uri &uri)
      : m_service(svc), m_uri(uri) {

      if ( m_uri.is_valid() ) {
        if ( m_uri.has_scheme("file") )
          m_source.reset(new FileUriSource(m_service, m_uri));
      }

    }

    UriSource::~UriSource() {
    }

    UriSaver::UriSaver(std::ostream &output, std::unique_ptr<UriSource> src, std::size_t chunk_size)
      : m_output(output),
        m_source(std::move(src)),
        m_buffer(chunk_size) {
    }

    UriSaver::~UriSaver() {
    }

    void UriSaver::async_save(std::function<void(ErrorCode)> cb) {
      m_source->source().async_fetch_some
        (boost::asio::buffer(m_buffer),
         [this, cb](ErrorCode ec, std::size_t read) {
          if ( ec ) {
            m_output.write((const char *)m_buffer.data(), m_buffer.size());
            if ( read < m_buffer.size() ) {
              cb(success);
            } else
              async_save(cb);
          } else
            cb(ec);
        });
    }

    UriFetcher::UriFetcher(std::unique_ptr<UriSource> src, std::size_t max_size)
      : m_source(std::move(src)), m_max_size(max_size) {
    }

    UriFetcher::~UriFetcher() {
    }

    void UriFetcher::async_fetch(std::function<void(ErrorCode, const std::string&)> cb) {
      std::size_t max_size = m_max_size;
      if ( !has_max_size() )
        max_size = 8 * 1024;

      m_buffer.resize(max_size);

      if ( source().is_valid() ) {
        source().source().async_fetch_some
          (boost::asio::buffer(m_buffer), [this, cb](ErrorCode ec, std::size_t read) {
            if ( ec ) m_buffer.resize(read);
            else m_buffer.resize(0);

            cb(ec, m_buffer);
          });
      } else {
        m_buffer.resize(0);
        cb(invalid_source, m_buffer);
      }
    }
  }
}
