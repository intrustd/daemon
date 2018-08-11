#include <boost/log/trivial.hpp>
#include <boost/bind.hpp>
#include <boost/process.hpp>

#include "unarchiver.hpp"

namespace fs = boost::filesystem;
namespace bp = boost::process;

namespace stork {
  namespace util {
    Unarchiver::Unarchiver(boost::asio::io_service &svc,
                           const fs::path &input_path,
                           const fs::path &output_path)
      : m_service(svc), m_input_path(input_path),
        m_output_path(output_path) {
    }

    Unarchiver::~Unarchiver() {
    }

    void Unarchiver::proc_finished(std::function<void(bool)> cb, int ret, const std::error_code &ec) {
      if ( !ec ) {
        if ( ret == 0 )
          cb(true);
        else {
          BOOST_LOG_TRIVIAL(error) << "The unarchiving process returned an error: " << ret;
          cb(false);
        }
      } else {
        BOOST_LOG_TRIVIAL(error) << "Failed to execute unarchiving process " << ec;
        cb(false);
      }
    }

    void Unarchiver::async_unzip(std::function<void(bool)> cb) {
      std::string ext;

      for ( auto cur = m_input_path ; cur.has_extension(); cur = cur.stem() ) {
        ext = cur.extension().string() + ext;
      }

      fs::create_directories(m_output_path.string());

      BOOST_LOG_TRIVIAL(debug) << "Attempting to unpack archive with extension: " << ext;

      auto abs_input_path(fs::absolute(m_input_path));
      // TODO probably need shared ptrs or something
      if ( ext == ".tar.xz" ) {
        m_proc = std::make_shared<bp::child>
          (bp::search_path("tar"), "xJf", abs_input_path.string(), m_service,
           bp::start_dir(m_output_path.string()),
           bp::on_exit(boost::bind(&Unarchiver::proc_finished, this, cb, _1, _2)));

      } else if ( ext == ".tar.bz2" ) {
        m_proc = std::make_shared<bp::child>
          (bp::search_path("tar"), "xjf", abs_input_path.string(), m_service,
           bp::start_dir(m_output_path.string()),
           bp::on_exit(boost::bind(&Unarchiver::proc_finished, this, cb, _1, _2)));

      } else if ( ext == ".tar.gz" ) {
        m_proc = std::make_shared<bp::child>
          (bp::search_path("tar"), "xzf", abs_input_path.string(), m_service,
           bp::start_dir(m_output_path.string()),
           bp::on_exit(boost::bind(&Unarchiver::proc_finished, this, cb, _1, _2)));

      } else if ( ext == ".zip" ) {
        m_proc = std::make_shared<bp::child>
          (bp::search_path("unzip"), abs_input_path.string(), m_service,
           bp::start_dir(m_output_path.string()),
           bp::on_exit(boost::bind(&Unarchiver::proc_finished, this, cb, _1, _2)));
      } else {
        cb(false);
        return;
      }
    }
  }
}
