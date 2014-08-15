#ifndef jachor_ip__
#define jachor_ip__

#include <stdint.h>
#include <cstddef>

namespace ip
{
    const std::size_t mac_size(6);
    const std::size_t addr_size(4);
    const std::size_t mac_addr_text(4 * 4);
    const std::size_t mac_text(6 * 3);

    struct Config {
        uint8_t mac[mac_size];
        uint8_t address[addr_size];
        uint8_t netmask[addr_size];
        uint8_t gateway[addr_size];
    };

    extern Config config;

    char parse_addr(uint8_t *out, const char *addr);
    char parse_mac(uint8_t *out, const char *addr);
    int print_addr(char *buf, const uint8_t *addr);
    int print_mac(char *buf, const uint8_t *mac);

    uint16_t read16(const uint8_t *ptr);
    uint32_t read32(const uint8_t *ptr);
    void write16(uint8_t *buf, uint16_t value);
    void write32(uint8_t *buf, uint32_t value);
}

#endif
