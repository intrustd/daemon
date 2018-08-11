#include <boost/test/unit_test.hpp>
#include <iostream>
#include "peer/session.hpp"

BOOST_AUTO_TEST_CASE( parse_session_description )
{
  const std::string sdp[] = {
    "v=0\n",
    "o=- 5701164415411578456 2 IN IP4 127.0.0.1\n",
    "s=-\n",
    "t=0 0\n",
    "a=group:BUNDLE data\n",
    "a=msid-semantic: WMS\n",
    "m=application 9 DTLS/SCTP 5000\n",
    "c=IN IP4 0.0.0.0\n",
    "a=ice-ufrag:R8ca\n",
    "a=ice-pwd:AD4Hc3VcHOwE6Pdz1vfl047Q\n",
    "a=ice-options:trickle\n",
    "a=fingerprint:sha-256 0E:7B:EA:8A:72:B2:A7:E9:4E:27:C4:9E:66:06:E2:99:24:EF:EC:93:F1:D1:ED:2E:C2:EF:C1:2F:87:1D:E5:5F\n",
    "a=setup:actpass\n",
    "a=mid:data\n",
    "a=sctpmap:5000 webrtc-datachannel 1024\n"
  };
  stork::peer::SessionParser parser;
  for ( std::size_t i = 0; i < sizeof(sdp) / sizeof(sdp[0]); ++ i )
    parser.parse_more(sdp[i]);

  parser.finish();

  if ( !parser.valid() )
    std::cerr << "Parser fails: " << parser.error_string() << " at " <<
      parser.current_line() << ":" << parser.current_column() << std::endl;
  BOOST_TEST(parser.valid());

  stork::peer::SessionDescription d(std::move(parser.steal_session()));
  BOOST_TEST(d.version == 0);
  BOOST_TEST(d.user_name == "-");
  BOOST_TEST(d.session_id == "5701164415411578456");
  BOOST_TEST(d.session_version == "2");
  BOOST_TEST(d.session_name == "-");
  BOOST_TEST(d.unicast_address.is_v4());
  BOOST_TEST(d.unicast_address.to_string() == "127.0.0.1");

  BOOST_TEST(d.attributes.size() == 2);

  auto sattr(d.attributes.begin());
  BOOST_TEST(sattr->first == "group");
  BOOST_TEST(sattr->second == "BUNDLE data");

  sattr++;
  BOOST_TEST(sattr->first == "msid-semantic");
  BOOST_TEST(sattr->second == " WMS");

  BOOST_TEST(d.streams.size() == 1);
  auto stream(d.streams.begin());

  BOOST_TEST(stream->media_type == "application");
  BOOST_TEST(stream->media_title == "");
  BOOST_TEST(stream->port_start == 9);
  BOOST_TEST(stream->port_count == 1);
  BOOST_TEST(stream->media_protocol == stork::peer::MediaStreamDescription::DTLS_SCTP);
  BOOST_TEST(stream->media_format == "5000");

  //BOOST_TEST(d->connection

  BOOST_TEST(stream->attributes.size() == 7);
  sattr = stream->attributes.begin();

  BOOST_TEST(sattr->first == "ice-ufrag");
  BOOST_TEST(sattr->second == "R8ca");
  sattr++;

  BOOST_TEST(sattr->first == "ice-pwd");
  BOOST_TEST(sattr->second == "AD4Hc3VcHOwE6Pdz1vfl047Q");
  sattr++;

  BOOST_TEST(sattr->first == "ice-options");
  BOOST_TEST(sattr->second == "trickle");
  sattr++;

  BOOST_TEST(sattr->first == "fingerprint");
  BOOST_TEST(sattr->second == "sha-256 0E:7B:EA:8A:72:B2:A7:E9:4E:27:C4:9E:66:06:E2:99:24:EF:EC:93:F1:D1:ED:2E:C2:EF:C1:2F:87:1D:E5:5F");
  sattr++;

  BOOST_TEST(sattr->first == "setup");
  BOOST_TEST(sattr->second == "actpass");
  sattr++;

  BOOST_TEST(sattr->first == "mid");
  BOOST_TEST(sattr->second == "data");
  sattr++;

  BOOST_TEST(sattr->first == "sctpmap");
  BOOST_TEST(sattr->second == "5000 webrtc-datachannel 1024");
}
