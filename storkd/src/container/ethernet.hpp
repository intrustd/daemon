#ifndef __stork_container_ethernet_HPP__
#define __stork_container_ethernet_HPP__

#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

namespace stork {
  namespace container {
    template<typename Body>
    struct EthPacket {
      struct ether_header hdr;
      Body pkt;

      template<typename T>
      inline T after(std::size_t ofs = 0) const { return (T) (_after + ofs); }

    private:
      char _after[];
    } __attribute__((packed));

    typedef EthPacket<struct arphdr> ArpPacket;
    typedef EthPacket<struct iphdr> IpPacket;

    struct ArpIPV4Response {
      struct arphdr hdr;
      std::uint8_t src_hw_addr[ETH_ALEN];
      std::uint32_t src_hw_ip;
      std::uint8_t tgt_hw_addr[ETH_ALEN];
      std::uint32_t  tgt_hw_ip;
    } __attribute__((packed));

    struct IcmpEchoReply {
      struct iphdr ip;
      struct icmphdr icmp;
    } __attribute__((packed));

    struct UdpPacket {
      struct iphdr ip;
      struct udphdr udp;
    } __attribute__((packed));

    inline std::uint16_t calc_ip_checksum(std::uint16_t *words, std::size_t tot_len) {
      std::uint32_t a(0);

      for ( std::size_t i = 0; i < tot_len; ++i )
        a += ntohs(words[i]);

      std::uint8_t carry((a >> 16) & 0xF);
      a &= 0xFFFF;

      std::uint16_t checksum(a);
      checksum += carry;

      return ~checksum;
    }

    inline std::uint16_t calc_ip_checksum(struct iphdr *ip) {
      std::uint16_t *words((std::uint16_t *)ip);
      std::size_t tot_len(ip->ihl * 2);

      return calc_ip_checksum(words, tot_len);
    }
  }
}

#endif
