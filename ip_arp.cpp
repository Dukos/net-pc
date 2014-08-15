#include "ip_internal.h"
#include "ip_hw.h"
#include "ip.h"

#include <string.h>
#include <stdio.h>

#define ARP_CACHE_SIZE      (8)

ip_return_t ip_handle_arp() {
    struct arp_message msg;
    ip_rx_read(&msg, ETH_HEADER_SIZE, ARP_MESSAGE_SIZE);

    // czy zgadzają się typy protokołów?
    if(read16(msg.htype) != ARP_HTYPE_ETHERNET)
        return RETURN_FINISHED;
    if(read16(msg.ptype) != ARP_PTYPE_IP)
        return RETURN_FINISHED;
    if(msg.hlen != ip::mac_size || msg.plen != ip::addr_size)
        return RETURN_FINISHED;

    // TODO: dodaj msg.spa, msg.sha do tablicy ARP
    printf("arp ip .%d = mac :%02x\n", msg.spa[3], msg.sha[5]);

    // czy to do mnie?
    if(memcmp(msg.tpa, config.address, ip::addr_size) != 0)
        return RETURN_FINISHED;

    if(read16(msg.oper) != ARP_OPER_REQUEST)
        return RETURN_FINISHED;

    printf("arp tx?\n");
    // TODO: zacznij wysylanie
    ip_return_t r = ip_tx_begin(msg.sha, ETH_PROTO_ARP);
    if(r != RETURN_FINISHED)
        return r;

    // ustaw docelowe na źródłowe adresy
    memcpy(msg.tpa, msg.spa, ip::addr_size);
    memcpy(msg.tha, msg.sha, ip::mac_size);
    // wpisz swoje dane w źródłowych adresach
    memcpy(msg.spa, ip::config.address, ip::addr_size);
    memcpy(msg.sha, ip::config.mac, ip::mac_size);
    // ustaw kod operacji na odpowiedź
    write16(msg.oper, ARP_OPER_RESPONSE);

    ip_tx_write(&msg, ETH_HEADER_SIZE, sizeof(msg));
    printf("arp tx!\n");
    return ip_tx_end(sizeof(msg) + ETH_HEADER_SIZE);
}

ip_return_t ip_query_arp(const uint8_t *ip_addr) {
    // zacznij wysylanie
    ip_return_t r = ip_tx_begin(ip_mac_broadcast, ETH_PROTO_ARP);
    if(r != RETURN_FINISHED)
        return r;

    struct arp_message msg;
    write16(msg.htype, ARP_HTYPE_ETHERNET);
    write16(msg.ptype, ARP_PTYPE_IP);
    msg.hlen = ip::mac_size;
    msg.plen = ip::addr_size;
    memcpy(msg.sha, ip::config.mac, ip::mac_size);
    memcpy(msg.spa, ip::config.address, ip::addr_size);
    memset(msg.tha, 0, ip::mac_size);
    memcpy(msg.tpa, ip_addr, ip::mac_size);
    ip::write16(msg.oper, ARP_OPER_REQUEST);

    ip_tx_write(&msg, ETH_HEADER_SIZE, sizeof(msg));
    printf("arp tx req!\n");
    return ip_tx_end(sizeof(msg) + ETH_HEADER_SIZE);
}


