#include <iomanip>
#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <sstream>

#include "backend.hpp"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace stork {
  namespace backend {

    // Backends

    static int default_curve_nid = NID_secp521r1;

    IBackend::~IBackend() {}
    IPersona::~IPersona() {}
    IApplication::~IApplication() {}

    class FilePersona : public IPersona {
    public:
      virtual ~FilePersona() {};

      virtual const PersonaId &persona_id() const {
        return m_persona_id;
      }

      virtual void async_install_application(const application::ApplicationIdentifier &id,
                                             std::function<void(std::error_code)> completion) {
        auto perms_file(persona_app_perm_file(id));

        if ( !fs::create_directories(perms_file.parent_path()) ) {
          // TODO better errors
          completion(std::make_error_code(std::errc::no_such_file_or_directory));
          return;
        }

        std::fstream perm(perms_file.string().c_str(), std::fstream::out);
        perm << "installed";
      }

      virtual void async_check_application_installed(const application::ApplicationIdentifier &id,
                                                     std::function<void(bool)> completion) {
        auto perms_file(persona_app_perm_file(id));

        BOOST_LOG_TRIVIAL(debug) << "Async_check_application installed: " << perms_file;
        if ( fs::is_regular_file(perms_file) ) {
          BOOST_LOG_TRIVIAL(debug) << "   this was a regular file";
          std::fstream perms(perms_file.string().c_str(), std::fstream::in);
          if ( perms.is_open() ) {
            std::string perm;
            std::getline(perms, perm);
            BOOST_LOG_TRIVIAL(debug) << "  got permission " << perm;
            if ( perm == "installed" )
              completion(true);
            else
              completion(false);
          } else
            completion(false);
        } else
          completion(false);
      }

      bool exists() {
        return fs::is_directory(persona_directory()) &&
          fs::is_regular_file(public_key_file()) &&
          fs::is_regular_file(private_key_file()) &&
          fs::is_regular_file(persona_file());
      }

      fs::path persona_directory() const {
        fs::path persona_path(m_backend.personas_dir());
        persona_path /= m_persona_id.id();
        return persona_path;
      }

      fs::path persona_perms_directory() const {
        return persona_directory() / "perms";
      }

      fs::path persona_app_perm_file(const application::ApplicationIdentifier &id) const {
        return persona_directory() / "perms" / id.domain() / id.app_id();
      }

      fs::path public_key_file() const {
        fs::path p(persona_directory());
        p /= "id.pub";
        return p;
      }

      fs::path private_key_file() const {
        fs::path p(persona_directory());
        p /= "id";
        return p;
      }

      fs::path persona_file() const {
        fs::path p(persona_directory());
        p /= "profile.json";
        return p;
      }

      bool ready_directory() const {
        if ( !fs::create_directories(persona_perms_directory()) ) {
          BOOST_LOG_TRIVIAL(error) << "Could not create persona directory " << persona_directory();
          return false;
        }
        return true;
      }

      bool write_public_key(const std::string &d) const {
        std::fstream f(public_key_file().string(), std::fstream::out);
        f << d;
        return true;
      }

      bool write_private_key(const std::string &d) const {
        std::fstream f(private_key_file().string(), std::fstream::out);
        f << d;
        return true;
      }

      bool write_profile(const persona::Profile &p) const {
        pt::ptree props;
        p.build_property_tree(props);

        std::fstream f(persona_file().string(), std::fstream::out);
        pt::write_json(f, props);

        return true;
      }


    private:
      FilePersona(FileBackend &be, const PersonaId &persona_id)
        : m_backend(be), m_persona_id(persona_id) {
      }

      FileBackend &m_backend;
      PersonaId m_persona_id;

      friend class FileBackend;
    };

    class FileApplication : public IApplication {
    public:
      virtual ~FileApplication() {};

      fs::path manifest_path() const {
        fs::path r(m_app_dir);
        r /= "manifest.json";
        return r;
      }

      fs::path uninstalled_marker_path() const {
        fs::path r(m_app_dir);
        r /= ".uninstalled";
        return r;
      }

      virtual std::shared_ptr<std::istream> get_manifest_input_stream() {
        return std::shared_ptr<std::istream>(new std::fstream(manifest_path().string(), std::fstream::in));
      }

      virtual fs::path channel_archive_path() {
        fs::path r(m_app_dir);
        r /= "nixexprs.tar.xz";
        return r;
      }

      virtual fs::path application_build_path() {
        fs::path r(m_app_dir);
        r /= "result";
        return r;
      }

      virtual fs::path application_channel_path() {
        fs::path r(m_app_dir);
        r /= "channel";
        return r;
      }

      virtual fs::path application_log_path() {
        fs::path r(m_app_dir);
        r /= "logs";
        return r;
      }

      bool is_installed() {
        return fs::is_directory(m_app_dir) &&
          fs::is_regular_file(manifest_path()) &&
          !fs::exists(uninstalled_marker_path());
      }

      // TODO If updating manifest, write to a temp file, unlink the old file, and then rename.
      void update_manifest(const application::ApplicationManifest &mf) const {
        pt::ptree pt;

        ensure_app_dir_exists();

        mf.write_to_ptree(pt);

        std::fstream manifest(manifest_path().string(), std::fstream::out);
        pt::write_json(manifest, pt);
      }

      void ensure_app_dir_exists() const {
        fs::create_directories(m_app_dir);
      }

    private:
      FileApplication(FileBackend &be, const fs::path &app_dir)
        : m_backend(be), m_app_dir(app_dir) {
      }

      FileBackend &m_backend;
      fs::path m_app_dir;

      friend class FileBackend;
    };

    FileBackend::FileBackend(boost::asio::io_service &svc, const fs::path &stork_dir)
      : m_io_service(svc), m_flock_strand(svc),
        m_stork_dir(stork_dir) {
    }

    FileBackend::~FileBackend() {
    }

    fs::path FileBackend::apps_dir() const {
      fs::path apps(stork_dir());
      apps /= "apps";
      return apps;
    }

    fs::path FileBackend::app_dir(const application::ApplicationIdentifier &id) const {
      fs::path app(apps_dir());
      std::stringstream app_path;
      app_path << id.domain() << ":" << id.app_id();
      app /= app_path.str();
      return app;
    }

    fs::path FileBackend::personas_dir() const {
      fs::path ps(stork_dir());
      ps /= "personas";
      return ps;
    }

    std::shared_ptr<IPersona> FileBackend::new_persona(const persona::Profile &profile) {
      std::shared_ptr<EC_KEY> key(EC_KEY_new_by_curve_name(default_curve_nid), EC_KEY_free);

      if ( !EC_KEY_generate_key(key.get()) )
        return std::shared_ptr<IPersona>();

      std::shared_ptr<BIO> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
      PEM_write_bio_EC_PUBKEY(pubkey_bio.get(), key.get());

      std::string pubkey_string;
      pubkey_string.resize(BIO_pending(pubkey_bio.get()));
      BIO_read(pubkey_bio.get(), pubkey_string.data(), pubkey_string.size());

      // Now hash the public key into a sha256hash
      std::uint8_t raw_digest[SHA256_DIGEST_LENGTH];
      SHA256((const std::uint8_t *) pubkey_string.c_str(), pubkey_string.size(), raw_digest);
      std::stringstream pubkey_hash;

      std::for_each(raw_digest, raw_digest + SHA256_DIGEST_LENGTH,
                    [&pubkey_hash](std::uint8_t c) {
                      pubkey_hash << std::setfill('0') << std::setw(2) << std::hex << (unsigned int) c;
                    });

      PersonaId persona_id(pubkey_hash.str());
      if ( !persona_id.is_valid() ) {
        BOOST_LOG_TRIVIAL(error) << "Invalid persona id: " << pubkey_hash.str();
        return std::shared_ptr<IPersona>();
      }

      std::shared_ptr<FilePersona> persona(new FilePersona(*this, persona_id));

      if ( !persona->ready_directory() )
        return std::shared_ptr<IPersona>();

      persona->write_public_key(pubkey_string);

      std::shared_ptr<BIO> privkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
      PEM_write_bio_ECPrivateKey(privkey_bio.get(), key.get(), NULL, NULL, 0, NULL, NULL);

      std::string privkey_string;
      privkey_string.resize(BIO_pending(privkey_bio.get()));
      BIO_read(privkey_bio.get(), privkey_string.data(), privkey_string.size());

      persona->write_private_key(privkey_string);
      persona->write_profile(profile);

      return persona;
    }

    void FileBackend::async_get_persona(const PersonaId &p,
                                        std::function<void(std::shared_ptr<IPersona>)> completion) {
      std::shared_ptr<FilePersona> persona(new FilePersona(*this, p));
      if ( persona->exists() )
        completion(persona);
      else
        completion(nullptr);
    }

    std::list< std::shared_ptr<IPersona> > FileBackend::list_personas() {
      std::list< std::shared_ptr<IPersona> > personas;
      fs::path cur_personas_dir(personas_dir());

      if ( !fs::exists(cur_personas_dir) )
        fs::create_directories(cur_personas_dir);

      for ( auto dir : fs::directory_iterator(cur_personas_dir) ) {
        auto persona_path(dir.path());
        auto profile_json_path(persona_path);
        profile_json_path /= "profile.json";


        if ( fs::is_regular_file(profile_json_path) ) {
          personas.push_back(std::shared_ptr<FilePersona>(new FilePersona(*this, PersonaId(persona_path.filename().string()))));
        }
      }

      return std::move(personas);
    }

    std::list< std::shared_ptr<IApplication> > FileBackend::list_installed_applications() {
      fs::path apps(apps_dir());
      std::list< std::shared_ptr<IApplication> > ret;

      if ( !fs::is_directory(apps) ) {
        if ( fs::exists(apps) ) {
          BOOST_LOG_TRIVIAL(error) << "apps/ directory is not a directory";
          return ret;
        } else
          fs::create_directory(apps);
      }

      for ( auto app_dir_entry: fs::directory_iterator(apps) ) {
        std::shared_ptr<FileApplication> app(new FileApplication(*this, app_dir_entry.path()));
        if ( app->is_installed() )
          ret.push_front(app);
      }

      return ret;
    }

    std::shared_ptr<IApplication> FileBackend::register_application(const application::ApplicationManifest &mf) {
      fs::path this_app_dir(app_dir(mf.identifier()));
      std::shared_ptr<FileApplication> ret(new FileApplication(*this, this_app_dir));

      ret->update_manifest(mf);
      return ret;
    }

    bool FileBackend::is_installed(const application::ApplicationIdentifier &id) {
      fs::path this_app_dir(app_dir(id));
      FileApplication this_app(*this, this_app_dir);

      return this_app.is_installed();
    }

    void FileBackend::save_flocks(const std::string &flock_data) {
      fs::path flock_data_path(m_stork_dir);
      flock_data_path /= "flocks";

      m_flock_strand.post([flock_data_path{std::move(flock_data_path)}, flock_data] () {
          std::fstream flock_data_file(flock_data_path.string(), std::fstream::out);
          flock_data_file << flock_data;
        });
    }

    void FileBackend::async_read_flocks(std::function<void(std::istream&)> cb) {
      fs::path flock_data_path(m_stork_dir);
      flock_data_path /= "flocks";

      m_flock_strand.post([flock_data_path{std::move(flock_data_path)}, cb{std::move(cb)}]() {
          if ( fs::is_regular_file(flock_data_path) ) {
            std::fstream flock_data_stream(flock_data_path.string(), std::fstream::in);
            cb(flock_data_stream);
          } else {
            std::stringstream flock_data_stream;
            cb(flock_data_stream);
          }
        });
    }

    void FileBackend::async_check_credentials(const LoginCredentials &creds, std::function<void(std::error_code)> cb) {
      // First check if tthe persona exists
      async_get_persona
        (creds.persona_id(),
         [cb{std::move(cb)}] (std::shared_ptr<IPersona> persona) {
          if ( !persona ) {
            cb(std::make_error_code(std::errc::file_exists));
          } else {
            cb(std::error_code());
            //        if ( persona->check_credential(creds.credentials()) ) {
            //          cb(std::error_code());
            //        } else {
            //          cb(std::make_error_code(std::errc::permission_denied));
                            //        }
          }
        });
    }
  }
}

namespace std {
  std::size_t hash<stork::backend::PersonaId>::operator() (const stork::backend::PersonaId &pid) const {
    return hash<string>()(pid.id());
  }
}
