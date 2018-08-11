#include <boost/log/trivial.hpp>
#include <boost/program_options.hpp>

#include "configuration.hpp"
#include "manager.hpp"

namespace po = boost::program_options;

using namespace stork::flock::flockd;

int main(int argc, const char **argv) {
  Configuration conf(argc, argv);

  if ( conf.is_valid() ) {
    boost::asio::io_service svc;
    MemoryBackend be(svc);
    Manager mgr(svc, conf, be);
    return mgr.run();
  } else {
    conf.print_usage();
    return 1;
  }
}
