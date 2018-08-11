#include "session.hpp"
#include "parse_utils.hpp"

namespace stork {
  namespace peer {
    SessionParser::SessionParser(SessionDescription &d)
      : m_state(start),
        m_line_buf_pos(0), m_line(1),
        m_session(d),
        m_has_global_connection(false) {
    }

    char SessionParser::parse_tag() {
      char *r = current_line_start();

      if ( r[1] == '=' ) {
        m_current_line_pos += 2;
        return *r;
      } else {
        m_state = invalid_type;
        return '\0';
      }
    }

    void SessionParser::consume_rest(std::string &s) {
      s = std::string(current_line_start(), current_line_end());
      m_current_line_pos = m_line_buf_pos;
    }

    bool SessionParser::parse_exact(const char *s) {
      int i = 0;
      for ( ; s[i] != '\0' && current_line_start() != current_line_end(); i++ ) {
        if ( s[i] != *current_line_start() )
          return false;
        m_current_line_pos ++;
      }
      if ( s[i] != '\0' )
        return false;

      return true;
    }

    bool SessionParser::skip_space() {
      bool skipped = false;
      while ( current_line_start() != current_line_end() &&
              isspace(*current_line_start()) ) {
        m_current_line_pos ++;
        skipped = true;
      }
      return skipped;
    }

    void SessionParser::parse_until_raw(const char *&start, const char *&end, const char *delim) {
      start = current_line_start();
      end = current_line_start();

      for ( ;
            end != current_line_end() &&
              !strchr(delim, *end);
            end++ );

      m_current_line_pos += end - start;
    }

    void SessionParser::parse_until(std::string &s, const char *delim) {
      const char *start, *end;
      parse_until_raw(start, end, delim);
      s = std::string(start, end);
    }

    void SessionParser::parse_attribute(const char *&nms, const char *&nme,
                                        const char *&vls, const char *&vle) {
      vls = vle = NULL;
      parse_until_raw(nms, nme, ":");
      if ( nms == nme ) {
        m_state = missing_attribute_name;
      } else if ( current_line_start() != current_line_end() ) {
        // Parse value
        char colon;
        if ( !next_char(colon) || colon != ':' ) {
          m_state = missing_colon;
          return;
        }

        vls = current_line_start();
        vle = current_line_end();
        m_current_line_pos = m_line_buf_pos;

        if ( vle == vls )
          m_state = missing_attribute_value;
      }
    }

    void SessionParser::parse_new_media() {
      auto old_state(m_state);
      m_state = parsed_session_header;

      if ( old_state >= parsed_session_header && m_cur_media )
        m_session.add_media_stream(std::move(m_cur_media));

      m_cur_media = m_session.new_media_stream();

      const char *s, *e;
      parse_until_raw(s, e, " ");
      if ( s == e ) {
        m_state = invalid_media;
        return;
      }
      m_cur_media->set_media_type(s, e);
      if ( !skip_space() ) {
        m_state = invalid_media;
        return;
      }

      if ( !parse_positive_decimal(m_cur_media->port_start) ) {
        m_state = invalid_media;
        return;
      }

      if ( current_line_start() == current_line_end() ) {
        m_state = invalid_media;
        return;
      }

      if ( *current_line_start() == '/' ) {
        if ( !parse_positive_decimal(m_cur_media->port_count) ) {
          m_state = invalid_media;
          return;
        }
      }

      if ( !skip_space() ) {
        m_state = invalid_media;
        return;
      }

      parse_until_raw(s, e, " ");
      if ( names_equal(s, e, "DTLS/SCTP") ) {
        m_cur_media->media_protocol = MediaStreamDescription::DTLS_SCTP;
      } else {
        m_state = invalid_media;
        return;
      }

      if ( !skip_space() ) {
        m_state = invalid_media;
        return;
      }

      parse_until_raw(s, e, " ");
      if ( s == e ) {
        m_state = invalid_media;
        return;
      }
      m_cur_media->set_media_format(s, e);
    }

    void SessionParser::finish() {
      if ( m_state >= parsed_session_header ) {
        m_session.add_media_stream(std::move(m_cur_media));
      } else if ( valid() )
        m_state = no_media;
    }

    void SessionParser::parse_line() {
      m_current_line_pos = 0;
      m_line ++;

      char type = parse_tag();
      switch ( m_state ) {
      case start:
        // Expect 'v' tag
        if ( type == 'v' ) {
          if ( !parse_positive_decimal(m_session.version) )
            m_state = incompatible_version;
          else if ( m_session.version != 0 )
            m_state = incompatible_version;
          else
            m_state = parsed_session_version;
        } else
          m_state = invalid_type;
        break;

      case parsed_session_version:
        // Expect 'o' tag
        if ( type == 'o' ) {
          parse_until(m_session.user_name, " ");
          if ( !skip_space() ) {
            m_state = invalid_originator;
            goto done;
          }
          parse_until(m_session.session_id, " ");
          if ( !skip_space() ) {
            m_state = invalid_originator;
            goto done;
          }
          parse_until(m_session.session_version, " ");
          if ( !skip_space() ) {
            m_state = invalid_originator;
            goto done;
          }
          if ( !parse_exact("IN") ) {
            m_state = invalid_net_type;
            goto done;
          }
          skip_space();
          parse_exact("IP");

          char addr_type;
          if ( !next_char(addr_type) ) {
            m_state = invalid_addr_type;
            goto done;
          }

          switch ( addr_type ) {
          case '4':
          case '6':
            break;
          default:
            m_state = invalid_addr_type;
            goto done;
          }

          skip_space();

          std::string raw_address;
          boost::system::error_code ec;
          consume_rest(raw_address);
          // TODO allow FQDN here as well
          m_session.unicast_address = boost::asio::ip::address::from_string(raw_address, ec);
          if ( ec ) {
            m_state = invalid_address;
            goto done;
          }

          m_state = parsed_session_originator;
        } else
          m_state = invalid_type;
        break;

      case parsed_session_originator:
        // Expect 's' tag
        if ( type == 's' ) {
          // Parse s
          consume_rest(m_session.session_name);
          if ( m_session.session_name.size() > 0 )
            m_state = parsed_session_name;
          else
            m_state = invalid_session_name;
        } else
          m_state = invalid_type;
        break;

      case parsed_session_name:
        // Expect 'i' tag, or nothing
        m_state = parsed_session_information;
        if ( type == 'i' ) goto done;

      case parsed_session_information:
        // Expect 'u' tag or nothing
        m_state = parsed_session_uri;
        if ( type == 'u' ) goto done;

      case parsed_session_uri:
        // Expect 'e' tag or nothing
        m_state = parsed_session_email;
        if ( type == 'e') goto done;

      case parsed_session_email:
        // Expect 'p' tag or nothing
        m_state = parsed_session_phone;
        if ( type == 'p' ) goto done;

      case parsed_session_phone:
        // Expect 'c' tag or nothing
        m_state = parsed_session_connection;
        if ( type == 'c' ) {
          m_has_global_connection = true;
          // TODO Add global connection

          goto done;
        }

      case parsed_session_connection:
        m_state = parsed_session_bandwidth;
        if ( type == 'b' ) goto done;

      case parsed_session_bandwidth:
        m_state = parsed_session_time;
        if ( type == 't' ) {
          // TODO parse 't'.

          // TODO check bounds here
          goto done;
        }

      case parsed_session_time:
        m_state = parsed_session_recurrence;
        if ( type == 'r' ) goto done;

      case parsed_session_recurrence:
        m_state = parsed_session_zone;
        if ( type == 'z' ) goto done;

      case parsed_session_zone:
        m_state = parsed_session_enckey;
        if ( type == 'k' ) goto done;

      case parsed_session_enckey:
      case parsed_session_attribute:
        m_state = parsed_session_attribute;
        if ( type == 'a' ) {
          const char *nms, *nme, *vls, *vle;
          parse_attribute(nms, nme, vls, vle);
          if ( valid() ) {
            m_session.attribute(nms, nme, vls, vle);
          }
        } else if ( type == 'm' ) {
          parse_new_media();
        } else {
          m_state = invalid_type;
        }
        break;

      case parsed_session_header:
        // Expect 'i' tag
        m_state = parsed_media_title;
        if ( type == 'i' ) {
          // TODO Parse media title
          goto done;
        }

      case parsed_media_title:
        m_state = parsed_media_connection;
        if ( type == 'c' ) {
          // TODO parse connection
        } else if ( m_has_global_connection ) {
          m_cur_media->connection = m_global_connection;
        } else
          m_state = no_connection;
        break;

      case parsed_media_connection:
        m_state = parsed_media_bandwidth;
        if ( type == 'b' ) goto done;

      case parsed_media_bandwidth:
        m_state = parsed_media_enckey;
        if ( type == 'k' ) {
          // TODO parse enckey
          goto done;
        }

      case parsed_media_enckey:
      case parsed_media_attribute:
        if ( type == 'a' ) {
          const char *nms, *nme, *vls, *vle;
          parse_attribute(nms, nme, vls, vle);
          if ( valid() )
            m_cur_media->attribute(nms, nme, vls, vle);
        } else if ( type == 'm' ) {
          parse_new_media();
        } else
          m_state = invalid_type;
        break;

      default:
        if ( m_state >= last_error )
          m_state = invalid_state;
        break;
      }

    done:
      return;
    }

    const char *SessionParser::error_string() const {
      switch ( m_state ) {
      case line_too_long:
        return "Line too long";
      case invalid_type:
        return "Invalid type tag";
      case invalid_session_name:
        return "Invalid session name";
      case invalid_state:
        return "Invalid state encountered (internal)";
      case invalid_originator:
        return "Invalid originator";
      case invalid_media:
        return "Invalid media";
      case invalid_net_type:
        return "Invalid net type in originator (expect IN)";
      case invalid_addr_type:
        return "Invalid address type (expect IP4 or IP6)";
      case invalid_address:
        return "Invalid address string";
      case incompatible_version:
        return "Incompatible SDP version";
      case no_media:
        return "No media specified";
      case no_connection:
        return "No connection";
      case missing_attribute_name:
        return "Missing attribute name";
      case missing_attribute_value:
        return "Missing attribute value";
      case missing_colon:
        return "Missing colon";
      default:
        if ( m_state <= last_error )
          return "Unknown error";
        else
          return "Success";
      }
    }

    // SessionBuilder
    SessionBuilder::SessionBuilder(std::ostream &s)
      : m_output(s) {
    }

    SessionBuilder::~SessionBuilder() {
    }

    void SessionBuilder::build(SessionDescription &sdp) {
      m_output << "v=" << sdp.version << std::endl;
      m_output << "o=" << sdp.user_name << " " << sdp.session_id << " " << sdp.session_version
               << " IN ";
      if ( sdp.unicast_address.is_v4() ) {
        m_output << "IP4 ";
      } else if ( sdp.unicast_address.is_v6() ) {
        m_output << "IP6 ";
      }
      m_output << sdp.unicast_address << std::endl;

      m_output << "s=" << sdp.session_name << std::endl;;
      m_output << "t=0 0" << std::endl; // TODO

      sdp.serialize_attributes(*this);
      sdp.serialize_streams(*this);
    }

    void SessionBuilder::attribute(const char *name) {
      m_output << "a=" << name << std::endl;
    }

    void SessionBuilder::attribute(const char *name, const char *value) {
      m_output << "a=" << name << ":" << value << std::endl;
    }

    void SessionBuilder::stream(MediaStreamDescription &d) {
      m_output << "m=" << d.media_type << " " << d.port_start;
      if ( d.port_count != 1 )
        m_output << "/" << d.port_count;
      m_output << " ";
      switch ( d.media_protocol ) {
      case MediaStreamDescription::UDP:
        m_output << "UDP"; break;
      case MediaStreamDescription::DTLS_SCTP:
        m_output << "DTLS/SCTP"; break;
      case MediaStreamDescription::UNKNOWN:
      default:
        m_output << "UNKNOWN"; break;
      }
      m_output << " " << d.media_format << std::endl;

      m_output << "c=IN ";
      if ( d.connection.in_address.is_v4() )
        m_output << "IP4 ";
      else if ( d.connection.in_address.is_v6() )
        m_output << "IP6 ";
      m_output << d.connection.in_address << std::endl;

      d.serialize_attributes(*this);
    }

    ISessionAttributes::~ISessionAttributes() {}
    ISessionStreams::~ISessionStreams() {}

    // SessionDescription
    SessionDescription::SessionDescription()
      : version(0), user_name("-"), session_name("-") {
    }

    SessionDescription::~SessionDescription() {
    }

    // MediaStreamDescription
    MediaStreamDescription::MediaStreamDescription()
      : port_count(1) {
      media_type[0] = '\0';
    }

    MediaStreamDescription::~MediaStreamDescription() {
    }

    void MediaStreamDescription::set_media_type(const char *mts, const char *mte) {
      *(copy_max(mts, mte, media_type, media_type + sizeof(media_type) - 1)) = '\0';
    }

    void MediaStreamDescription::set_media_format(const char *mts, const char *mte) {
      *(copy_max(mts, mte, media_format, media_format + sizeof(media_format) - 1)) = '\0';
    }

    // ConnectionDescription
    ConnectionDescription::ConnectionDescription() {
    }
  }
}
