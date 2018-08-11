#include <boost/log/trivial.hpp>
#include <string>
#include <functional>
#include "application.hpp"

namespace stork {
  namespace application {
    ApplicationIdentifier::ApplicationIdentifier(const std::string &domain,
                                                 const std::string &app_id)
      : m_domain(domain), m_app_id(app_id) {
    }

    ApplicationIdentifier ApplicationIdentifier::from_canonical_url(const stork::uri::Uri &uri, bool &success) {
      if ( uri.has_scheme("stork+app") ) {
        auto i = uri.begin();
        if ( i == uri.end() ) {
          BOOST_LOG_TRIVIAL(debug) << "Invalid app uri: no app name";
          success = false;
          return ApplicationIdentifier();
        } else {
          success = true;

          std::string app_name((*i).first, (*i).afterLast);
          BOOST_LOG_TRIVIAL(debug) << " Parsed app id " << uri.host() << " " << app_name;
          return ApplicationIdentifier(uri.host(), app_name);
        }
      } else {
        BOOST_LOG_TRIVIAL(debug) << "Invalid stork+app scheme";
        success = false;
        return ApplicationIdentifier();
      }
    }

    std::string ApplicationIdentifier::canonical_url() const {
      std::stringstream r;
      r << "stork+app://" << m_domain << "/" << m_app_id;
      return r.str();
    }

    void ApplicationIdentifier::reset() {
      m_domain.clear();
      m_app_id.clear();
    }
  }
}

namespace std {
  std::size_t hash<stork::application::ApplicationIdentifier>::operator() (const stork::application::ApplicationIdentifier &id) const {
    return hash<string>()(id.domain()) ^ hash<string>()(id.app_id());
  }
}
