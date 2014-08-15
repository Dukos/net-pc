#include <stdio.h>
#include "ip_internal.h"
#include "ip_hw.h"
#include <string.h>

namespace ip
{
    Config config;
}

uint8_t ip_sender_mac[ip::mac_size];
uint8_t ip_sender_addr[ip::addr_size];

ip_return_t ip_handle() {
        uint16_t proto;
        {
            struct eth_header hdr;
            ip_rx_read(&hdr, 0, sizeof(hdr));

            memcpy(ip_sender_mac, hdr.sender, ip::mac_size);
            proto = read16(hdr.protocol);

            char addr_sender[ip::mac_text];
            char addr_target[ip::mac_text];
            ip::print_mac(addr_sender, hdr.sender);
            ip::print_mac(addr_target, hdr.target);

            //printf("Got packet from %s to %s using protocol 0x%04x\n", addr_sender, addr_target, proto);
        }

        switch(proto) {
        case ETH_PROTO_ARP:
            return ip_handle_arp();
        case ETH_PROTO_IP:
            return ip_handle_ip();
        }

        return RETURN_FINISHED; // nieznany proto
}

ip_return_t ip_handle_ip() {
    uint8_t proto;
    uint16_t data_offset;
    uint16_t data_length;
    {
        struct ip_header hdr;
        ip_rx_read(&hdr, ETH_HEADER_SIZE, sizeof(struct ip_header));

        /* sprawdź wersję IP, rozmiar i fragmentację */
        if( (hdr.version_ihl >> 4) != 4 )
            return RETURN_FINISHED; // zła wersja IP
        uint16_t ihl = 4 * (hdr.version_ihl&0xf);
        if(ihl < 20)
            return RETURN_FINISHED; // za krotki naglowek
        data_offset = ihl;
        if( read16(hdr.offset)&0x3fff )
            return RETURN_FINISHED; // nie obslugiwana fragmentacja IP

        data_length = read16(hdr.length) - data_offset;

        /* sprawdź sumę kontrolną */
        uint32_t sum = 0;
        uint8_t i;
        for(i=0;i<(hdr.version_ihl&0xf);i++) {
            uint8_t buf[4];
            ip_rx_read(buf, ETH_HEADER_SIZE + 4*i, 4);
            sum += read16(buf+0);
            sum += read16(buf+2);
        }
        sum = (sum&0xffff) + (sum>>16);
        sum = sum ^ 0xffff;
        if(sum != 0)
            return RETURN_FINISHED; // zle CRC

        proto = hdr.protocol;
        memcpy(ip_sender_addr, hdr.sender, ip::addr_size);
    }

    data_offset += ETH_HEADER_SIZE;
    //printf("got IP\n");

    switch(proto) {
    case IP_PROTO_ICMP:
        return ip_handle_icmp(data_offset, data_length);
    case IP_PROTO_TCP:
        return ip_handle_tcp(data_offset, data_length);
    }

    return RETURN_FINISHED;
}

void ip_tx_header(const uint8_t *target, uint8_t protocol, uint16_t payload_length) {
    struct ip_header hdr;
    hdr.version_ihl = 0x45;
    hdr.tos = 0x00;
    hdr.ident[0] = 0x00;
    hdr.ident[1] = 0x00;
    hdr.offset[0] = 0x40;
    hdr.offset[1] = 0;
    hdr.ttl = 64;
    hdr.protocol = protocol;
    hdr.checksum[0] = 0;
    hdr.checksum[1] = 0;
    memcpy(hdr.sender, ip::config.address, ip::addr_size);
    memcpy(hdr.target, target, ip::addr_size);
    ip::write16(hdr.length, payload_length+20);
    ip::write16(hdr.checksum, ip_checksum(&hdr, sizeof(hdr)));
    ip_tx_write(&hdr, ETH_HEADER_SIZE, sizeof(hdr));
}

