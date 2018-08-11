#include "profile.hpp"

namespace pt = boost::property_tree;

namespace stork {
  namespace persona {
    Profile::Profile(const std::string &full_name)
      : m_full_name(full_name) {
    }

    Profile::Profile(stork::proto::ProtoParser &p) {
      p.parseVarLenString("full name", m_full_name)
        .parseOptional("email tag", [this, &p]() {
            std::string email;
            p.parseVarLenString("email", email);
            m_email = std::move(email);
          });
    }

    void Profile::build_proto(stork::proto::ProtoBuilder &b) const {
      // TODO(travis) more robust support
      b.interVarLenString(m_full_name)
        .interOptional<std::string>
        (m_email, [this, &b](const std::string &email) {
          b.interVarLenString(email);
        });
    }

    void Profile::build_property_tree(pt::ptree &p) const {
      p.put("name", m_full_name);
      if ( m_email )
        p.put("email", *m_email);
    }
  }
}
