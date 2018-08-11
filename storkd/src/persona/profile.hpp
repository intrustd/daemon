#ifndef __stork_persona_profile_HPP__
#define __stork_persona_profile_HPP__

#include <string>
#include <boost/optional.hpp>
#include <boost/property_tree/ptree.hpp>

#include "../proto.hpp"

namespace stork {
  namespace persona {
    class Profile {
    public:
      inline Profile() {};
      Profile(const std::string &full_name);
      Profile (stork::proto::ProtoParser &p);

      inline const std::string &full_name() const { return m_full_name; }
      inline void full_name(const std::string &nm) { m_full_name = nm; }

      inline const boost::optional<std::string> &email() const { return m_email; }
      inline void email(const std::string &email) { m_email = email; }
      inline void unset_email() { m_email.reset(); }

      void build_proto(stork::proto::ProtoBuilder &b) const;
      void build_property_tree(boost::property_tree::ptree &pt) const;

    private:
      std::string m_full_name;
      boost::optional<std::string> m_email;
    };
  }
}

#endif
