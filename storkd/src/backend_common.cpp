#include "backend.hpp"
#include "proto.hpp"

namespace stork {
  namespace backend {
    // Login credentials

    void LoginCredentials::build_proto(proto::ProtoBuilder &b) const {
      b.interObject(m_persona_id).interVarLenString(m_credentials);
    }

    void LoginCredentials::parse_proto(proto::ProtoParser &p)  {
      p.parseObject("persona id", m_persona_id)
        .parseVarLenString("credentials", m_credentials);
    }
  }
}
