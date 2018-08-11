#ifndef __stork_peer_session_HPP__
#define __stork_peer_session_HPP__

#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <memory>
#include <list>

namespace stork {
  namespace peer {
    typedef std::list< std::pair<std::string, std::string> > sdp_attributes;

    class ConnectionDescription {
    public:
      ConnectionDescription();

      boost::asio::ip::address in_address;
    };

    class ISessionAttributes {
    public:
      virtual ~ISessionAttributes();
      virtual void attribute(const char *name) =0;
      virtual void attribute(const char *name, const char *value) =0;
    };

    class MediaStreamDescription {
    public:
      MediaStreamDescription();
      virtual ~MediaStreamDescription();

      enum MediaProtocol {
        UNKNOWN,
        UDP, // Unspecified UDP
        DTLS_SCTP // SCTP over DTLS
      };

      char media_type[32];
      std::uint16_t port_start, port_count;
      MediaProtocol media_protocol;
      char media_format[16];

      ConnectionDescription connection;

      void set_media_type(const char *mts, const char *mte);
      void set_media_format(const char *mfs, const char *mfe);

    private:
      virtual void attribute(const char *name_start, const char *name_end,
                             const char *value_start, const char *value_end) =0;
      virtual void serialize_attributes(ISessionAttributes &a) =0;

      friend class SessionBuilder;
      friend class SessionParser;
    };

    class ISessionStreams {
    public:
      virtual ~ISessionStreams();
      virtual void stream(MediaStreamDescription &d) =0;
    };

    class SessionDescription {
    public:
      SessionDescription();
      virtual ~SessionDescription();

      int version;
      std::string user_name, session_id, session_version, session_name;
      boost::asio::ip::address unicast_address;

    protected:
      virtual void attribute(const char *name_start, const char *name_end,
                             const char *value_start, const char *value_end) =0;
      virtual std::unique_ptr<MediaStreamDescription> new_media_stream() =0;
      virtual void add_media_stream(std::unique_ptr<MediaStreamDescription> d) =0;

      virtual void serialize_attributes(ISessionAttributes &b) =0;
      virtual void serialize_streams(ISessionStreams &b) =0;

      friend class SessionParser;
      friend class SessionBuilder;
    };

    class SessionBuilder : public ISessionAttributes,
                           public ISessionStreams {
    public:
      SessionBuilder(std::ostream &s);
      virtual ~SessionBuilder();

      void build(SessionDescription &sdp);

      virtual void attribute(const char *name);
      virtual void attribute(const char *name, const char *value);
      virtual void stream(MediaStreamDescription &d);

    private:
      std::ostream &m_output;
    };

    class SessionParser {
    public:
      SessionParser(SessionDescription &d);

      template<typename String>
      void parse_more(const String &s) {
        if ( valid() ) {
          bool newline = false;

          for ( char c : s ) {
            if ( m_line_buf_pos >= m_line_buffer.size() ) {
              m_state = line_too_long;
              return;
            }

            if ( newline ) {
              parse_line();
              newline = false;
              m_line_buf_pos = 0;

              if ( c != '\n' && valid() ) {
                m_line_buffer[m_line_buf_pos] = c;
              }
            } else if ( c == '\r' || c == '\n' ) {
              newline = true;
            } else {
              m_line_buffer[m_line_buf_pos] = c;
              m_line_buf_pos ++;
            }
          }

          if ( newline ) {
            parse_line();
            m_line_buf_pos = 0;
          }
        }
      }

      void finish();

      inline bool valid() const { return m_state > last_error; }

      const char *error_string() const;

      inline int current_line() const { return m_line - 1; }
      inline int current_column() const { return m_current_line_pos; }

    private:
      void parse_line();
      char parse_tag();

      template<typename N>
      bool parse_positive_decimal(N &n) {
        char *c(current_line_start()), *orig(c);
        n = 0;

        for ( ; c != current_line_end() && isdigit(*c); ++c ) {
          n *= 10;
          n += (*c - '0');
        }

        m_current_line_pos += c - orig;

        if ( (c - orig) == 0 )
          return false;
        else
          return true;
      }

      inline bool next_char(char &c) {
        if ( current_line_start() == current_line_end() ) {
          c = '\0';
          return false;
        } else {
          c = *current_line_start();
          m_current_line_pos ++;
          return true;
        }
      }

      void parse_until(std::string &s, const char* chrs);
      void parse_until_raw(const char *&s, const char *&e, const char *chrs);
      bool parse_exact(const char *s);
      bool skip_space();

      void consume_rest(std::string &s);
      void parse_attribute(const char *&nms, const char *&nme,
                           const char *&vls, const char *&vle);
      void parse_new_media();

      inline char *current_line_start() { return m_line_buffer.begin() + m_current_line_pos; }
      inline char *current_line_end() { return m_line_buffer.begin() + m_line_buf_pos; }

      enum session_parse_state {
        line_too_long,
        invalid_type,
        invalid_session_name,
        invalid_state,
        invalid_originator,
        invalid_net_type,
        invalid_addr_type,
        invalid_address,
        invalid_media,
        incompatible_version,
        no_media,
        no_connection,
        missing_attribute_name,
        missing_attribute_value,
        missing_colon,
        last_error,

        start,
        parsed_session_version,
        parsed_session_originator,
        parsed_session_name,
        parsed_session_information,
        parsed_session_uri,
        parsed_session_email,
        parsed_session_phone,
        parsed_session_connection,
        parsed_session_bandwidth,
        parsed_session_time,
        parsed_session_recurrence,
        parsed_session_zone,
        parsed_session_enckey,
        parsed_session_attribute,

        parsed_session_header,

        parsed_media_title,
        parsed_media_connection,
        parsed_media_bandwidth,
        parsed_media_enckey,
        parsed_media_attribute
      };

      session_parse_state m_state;

      std::uint32_t m_line_buf_pos, m_current_line_pos, m_line;
      boost::array<char, 4096> m_line_buffer;

      SessionDescription &m_session;

      bool m_has_global_connection;
      ConnectionDescription m_global_connection;

      std::unique_ptr<MediaStreamDescription> m_cur_media;
    };

  }
}

#endif
