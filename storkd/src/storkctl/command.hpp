#ifndef __stork_command_HPP__
#define __stork_command_HPP__

#include <iomanip>
#include <functional>
#include <boost/filesystem.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/positional_options.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/asio.hpp>
#include <boost/asio/local/stream_protocol.hpp>

#include "../local_proto.hpp"

namespace stork {
  namespace storkctl {
    class Command {
    public:
      virtual ~Command();

      virtual int run() =0;

      class Factory {
      public:
        inline Factory(const char *cmd_name, std::function<Command*(int, const char**)> factory)
          : m_command_name(cmd_name),
            m_factory(factory) {
        };

        inline std::string command_name() const { return m_command_name; }
        inline Command *build(int argc, const char **argv) const {
          return m_factory(argc, argv);
        }

      private:
        std::string m_command_name;
        std::function<Command*(int, const char **)> m_factory;
      };

    protected:
      Command();

      virtual void build_options_description() =0;
      void parse_args(int argc, const char **argv);

      std::ostream &info() const;

      inline const boost::program_options::variables_map &parsed_args() const {
        return m_arguments;
      }

      boost::program_options::options_description m_options;
      boost::program_options::positional_options_description m_positional;

    private:
      boost::program_options::variables_map m_arguments;
    };

    /**
     * Mixin for commands that accept a directory argument for the local API
     */
    class ApiCommandMixin : public Command {
    public:
      virtual ~ApiCommandMixin();

    protected:
      void parse_args(int argc, const char **argv);

      void send_command(boost::asio::local::stream_protocol::socket &socket,
                        const proto::local::Command &cmd);

      template <typename T>
      T simple_api_command(const proto::local::Command &cmd) {
        boost::asio::io_service svc;
        boost::asio::local::stream_protocol::socket socket(open_socket(svc));

        send_command(socket, cmd);

        return read_response<T>(socket);
      }

      template <typename T>
      T read_response(boost::asio::local::stream_protocol::socket &socket) {
        std::uint16_t resp_sz(0);
        boost::asio::read(socket, boost::asio::buffer(&resp_sz, sizeof(resp_sz)));
        resp_sz = ntohs(resp_sz);

        std::string response;
        response.resize(resp_sz);

        boost::asio::read(socket, boost::asio::buffer(response));

        std::stringstream resp_stream(response);
        proto::ProtoParser parser(resp_stream);
        return T(parser);
      }

      virtual bool api_required() const =0;
      virtual void build_options_description();

      boost::asio::local::stream_protocol::socket open_socket(boost::asio::io_service &svc) const;
      boost::filesystem::path m_stork_dir;
    };
  }
}

#endif
