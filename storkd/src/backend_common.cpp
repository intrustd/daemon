#include "backend.hpp"
#include "proto.hpp"

namespace stork {
  namespace backend {
    // Login credentials

    void LoginCredentials::build_proto(proto::ProtoBuilder &b) const {
      b.interObject(m_persona_id).interVarLenString(m_credentials)
        .inter(m_wants_user_admin)
        .interList(m_wanted_apps, [&b] (const application::ApplicationIdentifier &app_id) {
            b.interObject(app_id);
          });
    }

    void LoginCredentials::parse_proto(proto::ProtoParser &p)  {
      p.parseObject("persona id", m_persona_id)
        .parseVarLenString("credentials", m_credentials)
        .parse("wants user admin", m_wants_user_admin)
        .parseList("wanted apps", std::insert_iterator< std::unordered_set<application::ApplicationIdentifier> >(m_wanted_apps, m_wanted_apps.begin()),
                   [&p] () {
                     application::ApplicationIdentifier out;
                     p.parseObject("wanted app", out);
                     return out;
                   });
    }
  }
}
