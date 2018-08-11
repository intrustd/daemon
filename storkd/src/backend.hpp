#ifndef __stork_backend_HPP__
#define __stork_backend_HPP__

#include <boost/filesystem.hpp>
#include <unordered_set>

#include "application/application.hpp"
#include "persona/profile.hpp"
#include "proto.hpp"

namespace stork {
  namespace backend {
    class PersonaId {
    public:
      const std::size_t PERSONA_ID_LENGTH = 64;

      inline PersonaId() {}
      inline PersonaId(const std::string &id)
        : m_id(id) {
      }
      PersonaId(const PersonaId &p) = default;

      inline void build_proto(proto::ProtoBuilder &builder) const {
        builder.interFixedLenString(m_id, PERSONA_ID_LENGTH);
      }
      inline void parse_proto(proto::ProtoParser &parser) {
        parser.parseFixedLenString("persona id", m_id, PERSONA_ID_LENGTH);
      }

      inline bool is_valid() const {
        return m_id.size() == PERSONA_ID_LENGTH;
      }

      inline PersonaId &operator=(const PersonaId &d) {
        m_id = d.m_id;
        return *this;
      }

      inline bool operator ==(const PersonaId &a) const {
        return m_id == a.m_id;
      }

      inline const std::string &id() const { return m_id; }
    private:
      std::string m_id;
    };

    class LoginCredentials {
    public:
      inline LoginCredentials() { }
      inline LoginCredentials(const LoginCredentials &creds) = default;
      inline LoginCredentials(const backend::PersonaId &persona, const std::string &credentials)
        : m_persona_id(persona), m_credentials(credentials), m_wants_user_admin(false) {
      }
      inline LoginCredentials(LoginCredentials &&creds) = default;

      inline void request_user_admin() { m_wants_user_admin = true; }
      inline void give_up_user_admin() { m_wants_user_admin = false; }

      inline void request_app(const application::ApplicationIdentifier &id) { m_wanted_apps.insert(id); }
      inline void give_up_app(const application::ApplicationIdentifier &id) { m_wanted_apps.erase(id); }
      inline bool is_requesting_app(const application::ApplicationIdentifier &id) { return m_wanted_apps.find(id) != m_wanted_apps.end(); }

      void build_proto(proto::ProtoBuilder &b) const;

      void parse_proto(proto::ProtoParser &p);

      inline const std::string &credentials() const { return m_credentials; }
      inline const backend::PersonaId &persona_id() const { return m_persona_id; }
      inline bool wants_user_admin() const { return m_wants_user_admin; }
      inline const std::unordered_set<application::ApplicationIdentifier> &wanted_apps() const { return m_wanted_apps; }

    private:
      backend::PersonaId m_persona_id;
      std::string m_credentials;

      bool m_wants_user_admin;
      std::unordered_set<application::ApplicationIdentifier> m_wanted_apps;
    };

    class IPersona;
    class IApplication;

    class IBackend {
    public:
      virtual ~IBackend();

      virtual std::shared_ptr<IPersona> new_persona(const persona::Profile &p) =0;
      virtual std::list< std::shared_ptr<IPersona> > list_personas() =0;

      virtual std::list< std::shared_ptr<IApplication> > list_installed_applications() =0;
      virtual std::shared_ptr<IApplication> register_application(const application::ApplicationManifest &mf) =0;
      virtual bool is_installed(const application::ApplicationIdentifier &id) =0;
      virtual void save_flocks(const std::string &flock_data) =0;
      virtual void async_read_flocks(std::function<void(std::istream&)> cb) =0;

      virtual void async_check_credentials(const LoginCredentials &creds, std::function<void(std::error_code)> cb) =0;
    };

    class IApplication {
    public:
      virtual ~IApplication();

      virtual std::shared_ptr<std::istream> get_manifest_input_stream() =0;

      virtual boost::filesystem::path channel_archive_path() =0;
      virtual boost::filesystem::path application_build_path() =0;
      virtual boost::filesystem::path application_channel_path() =0;
      virtual boost::filesystem::path application_log_path() =0;
    };

    class IPersona {
    public:
      virtual ~IPersona();

      virtual const PersonaId &persona_id() const =0;
    };

    class FileBackend : public IBackend {
    public:
      FileBackend(boost::asio::io_service &svc, const boost::filesystem::path &stork_dir);
      virtual ~FileBackend();

      virtual std::shared_ptr<IPersona> new_persona(const persona::Profile &p);
      virtual std::list< std::shared_ptr<IPersona> > list_personas();

      virtual std::list< std::shared_ptr<IApplication> > list_installed_applications();
      virtual bool is_installed(const application::ApplicationIdentifier &id);
      virtual std::shared_ptr<IApplication> register_application(const application::ApplicationManifest &mf);

      virtual void save_flocks(const std::string &flock_data);
      virtual void async_read_flocks(std::function<void(std::istream&)> cb);

      virtual void async_check_credentials(const LoginCredentials &creds, std::function<void(std::error_code)> cb);;

      inline const boost::filesystem::path &stork_dir() const { return m_stork_dir; }
      inline boost::asio::io_service &io_service() const { return m_io_service; }

      boost::filesystem::path apps_dir() const;
      boost::filesystem::path app_dir(const application::ApplicationIdentifier &id) const;

      boost::filesystem::path personas_dir() const;

    private:
      boost::asio::io_service &m_io_service;
      boost::asio::io_service::strand m_flock_strand;

      boost::filesystem::path m_stork_dir;
    };
  }
}

#endif
