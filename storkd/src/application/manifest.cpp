#include <boost/log/trivial.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include "application.hpp"

namespace pt = boost::property_tree;

namespace stork {
  namespace application {
    ApplicationManifest::ApplicationManifest() {
    }

    ApplicationManifest::ApplicationManifest(std::istream &is) {
      pt::ptree pt;

      try {
        pt::read_json(is, pt);
        read_from_ptree(pt);
      } catch (pt::json_parser::json_parser_error &e) {
        BOOST_LOG_TRIVIAL(error) << "Could not read manifest: " << e.what();
        reset();
      }
    }

    ApplicationManifest::ApplicationManifest(pt::ptree &pt) {
      read_from_ptree(pt);
    }

    bool ApplicationManifest::is_valid() const {
      return m_name.size() > 0 && m_identifier.is_valid() &&
        m_nix_channel.is_valid() &&
        (!m_homepage || (*m_homepage).is_valid());
    }

    void ApplicationManifest::reset() {
      m_name.clear();
      m_identifier.reset();
      m_nix_channel.reset();
      m_author.reset();
      m_homepage.reset();
      m_categories.clear();
    }

    bool ApplicationManifest::read_from_ptree(pt::ptree &pt) {
      try {
        m_name = pt.get<std::string>("name");

        stork::uri::Uri identifier(pt.get<std::string>("identifier"));
        bool is_valid(false);
        m_identifier = ApplicationIdentifier::from_canonical_url(identifier, is_valid);
        if ( !is_valid ) {
          BOOST_LOG_TRIVIAL(debug) << "Invalid application identifier: " << identifier.raw();
          reset();
          return false;
        }

        m_nix_channel = pt.get<std::string>("nix-channel");

        m_author = pt.get_optional<std::string>("author");
        m_homepage = pt.get_optional<std::string>("homepage");

        m_categories.clear();
        for ( pt::ptree::value_type &v : pt.get_child("categories") ) {
          m_categories.push_back(v.second.data());
        }

        return true;
      } catch ( pt::ptree_bad_path& pt ) {
        reset();
        return false;
      }
    }

    void ApplicationManifest::write_to_ptree(boost::property_tree::ptree &pt) const {
      pt.put("name", m_name);
      pt.put("identifier", m_identifier.canonical_url());
      pt.put("nix-channel", m_nix_channel.raw());

      if (m_author) pt.put("author", *m_author);
      if (m_homepage) pt.put("homepage", (*m_homepage).raw());

      pt::ptree categories;
      for( const std::string &category : m_categories ) {
        pt::ptree category_json;
        category_json.put("", category);
        categories.push_back(std::make_pair("", category_json));
      }
      pt.add_child("categories", categories);
    }
  }
}
