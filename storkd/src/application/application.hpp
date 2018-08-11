#ifndef __stork_application_application_HPP__
#define __stork_application_application_HPP__

#include <list>
#include <boost/property_tree/ptree.hpp>
#include <boost/optional.hpp>

#include "../uri.hpp"
#include "../proto.hpp"

#undef major
#undef minor

namespace stork {
  namespace application {
    class ApplicationIdentifier {
    public:
      inline ApplicationIdentifier() {};
      ApplicationIdentifier(const std::string &domain,
                            const std::string &app_id);
      static ApplicationIdentifier from_canonical_url(const stork::uri::Uri &url, bool &success);

      std::string canonical_url() const;

      inline const std::string &domain() const { return m_domain; }
      inline const std::string &app_id() const { return m_app_id; }

      inline bool is_valid() const {
        return m_domain.size() > 0 && m_app_id.size() > 0;
      }

      inline bool operator==(const ApplicationIdentifier &b) const {
        return domain() == b.domain() && app_id() == b.app_id();
      }

      void reset();

      inline void parse_proto(proto::ProtoParser &p) {
        p.parseVarLenString("app id domain", m_domain)
          .parseVarLenString("app id", m_app_id);
      }
      inline void build_proto(proto::ProtoBuilder &b) const {
        b.interVarLenString(m_domain).interVarLenString(m_app_id);
      }

    private:
      std::string m_domain;
      std::string m_app_id;
    };


    class ApplicationVersion {
    public:
      ApplicationVersion(std::uint8_t major, std::uint8_t minor,
                         std::uint8_t revision, std::uint8_t rc);
      ~ApplicationVersion();

      inline std::uint8_t major() const { return m_major; }
      inline std::uint8_t minor() const { return m_minor; }
      inline std::uint8_t revision() const { return m_revision; }
      inline std::uint8_t rc() const { return m_rc; }

    private:
      std::uint8_t m_major, m_minor, m_revision, m_rc;
    };

    class ApplicationManifest {
    public:
      ApplicationManifest(std::istream &is);
      ApplicationManifest(boost::property_tree::ptree &pt);
      ApplicationManifest();

      inline const std::string &name() const { return m_name; }
      inline void name(const std::string &nm) { m_name = nm; }

      inline const ApplicationIdentifier &identifier() const { return m_identifier; }
      inline void identifier(const ApplicationIdentifier &id) { m_identifier = id; }

      inline const boost::optional<std::string> &author() const { return m_author; }
      inline void author(const std::string &author) { m_author = author; }
      inline void unset_author() { m_author.reset(); }

      inline const boost::optional<stork::uri::Uri> &homepage() const { return m_homepage; }
      inline void homepage(const stork::uri::Uri &hm) { m_homepage = hm; }
      inline void unset_homepage() { m_homepage.reset(); }

      inline const stork::uri::Uri &nix_channel() const { return m_nix_channel; }
      inline void nix_channel(const stork::uri::Uri &nix_channel) { m_nix_channel = nix_channel; }

      inline std::list<std::string> &categories() { return m_categories; }

      bool is_valid() const;

      /**
       * Read the manifest from a property tree.
       *
       * @returns 'true' if the properties were a valid manifest, 'false' otherwise.
       */
      bool read_from_ptree(boost::property_tree::ptree &pt);

      /**
       * Serialize the manifest to a property tree
       */
      void write_to_ptree(boost::property_tree::ptree &pt) const;

      void reset();

    private:
      std::string m_name;
      ApplicationIdentifier m_identifier;
      stork::uri::Uri m_nix_channel;

      boost::optional<std::string> m_author;
      boost::optional<stork::uri::Uri> m_homepage;

      std::list<std::string> m_categories;
    };
  }
}

namespace std {
  template<>
  struct hash<stork::application::ApplicationIdentifier> {
    std::size_t operator() (const stork::application::ApplicationIdentifier&) const;
  };
}

#endif
