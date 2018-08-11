#ifndef __stork_unarchiver_HPP__
#define __stork_unarchiver_HPP__

#include <boost/filesystem.hpp>
#include <boost/process.hpp>
#include <boost/asio.hpp>

namespace stork {
  namespace util {
    class Unarchiver {
    public:
      Unarchiver(boost::asio::io_service &svc,
                 const boost::filesystem::path &input_path,
                 const boost::filesystem::path &output_path);
      ~Unarchiver();

      void async_unzip(std::function<void(bool)> cb);

    private:
      void proc_finished(std::function<void(bool)> cb,
                         int ret, const std::error_code &ec);

      boost::asio::io_service &m_service;
      boost::filesystem::path m_input_path, m_output_path;

      std::shared_ptr<boost::process::child> m_proc;
    };
  }
}

#endif
