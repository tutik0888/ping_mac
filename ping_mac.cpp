#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

// Заготовка для ICMP ping и получения MAC-адреса
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <IPv4 address>" << std::endl;
        return 1;
    }
    const char* target_ip = argv[1];

    // Функция для вычисления контрольной суммы
    auto checksum = [](void* vdata, size_t length) -> uint16_t {
        char* data = (char*)vdata;
        uint32_t acc = 0;
        for (size_t i = 0; i + 1 < length; i += 2) {
            uint16_t word;
            memcpy(&word, data + i, 2);
            acc += ntohs(word);
        }
        if (length & 1) {
            uint16_t word = 0;
            memcpy(&word, data + length - 1, 1);
            acc += ntohs(word);
        }
        while (acc >> 16) acc = (acc & 0xFFFF) + (acc >> 16);
        return htons(~acc);
    };

    // Создание raw socket для ICMP
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    // Заполнение структуры назначения
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, target_ip, &addr.sin_addr) != 1) {
        std::cerr << "Invalid IPv4 address" << std::endl;
        return 1;
    }

    // Формирование ICMP Echo Request
    char packet[64] = {0};
    struct icmphdr* icmp = (struct icmphdr*)packet;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(getpid() & 0xFFFF);
    icmp->un.echo.sequence = htons(1);
    // Данные после заголовка ICMP
    strcpy(packet + sizeof(struct icmphdr), "ping_mac_util");
    size_t packet_size = sizeof(struct icmphdr) + strlen("ping_mac_util");
    icmp->checksum = 0;
    icmp->checksum = checksum(packet, packet_size);

    // Отправка ICMP Echo Request
    ssize_t sent = sendto(sock, packet, packet_size, 0, (sockaddr*)&addr, sizeof(addr));
    if (sent < 0) {
        perror("sendto");
        close(sock);
        return 1;
    }
    std::cout << "ICMP Echo Request sent to " << target_ip << std::endl;

    // Получение ICMP Echo Reply и извлечение MAC-адреса
    // Открываем raw socket на уровне Ethernet
    int eth_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (eth_sock < 0) {
        perror("socket(AF_PACKET)");
        close(sock);
        return 1;
    }
    bool found = false;
    for (int attempt = 0; attempt < 10 && !found; ++attempt) {
        uint8_t buf[2048];
        ssize_t len = recv(eth_sock, buf, sizeof(buf), 0);
        if (len < 0) {
            perror("recv");
            break;
        }
        struct ethhdr* eth = (struct ethhdr*)buf;
        if (ntohs(eth->h_proto) != ETH_P_IP) continue;
        struct iphdr* ip = (struct iphdr*)(buf + sizeof(struct ethhdr));
        if (ip->protocol != IPPROTO_ICMP) continue;
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
        if (strcmp(src_ip, target_ip) != 0) continue;
        struct icmphdr* icmp_reply = (struct icmphdr*)(buf + sizeof(struct ethhdr) + ip->ihl * 4);
        if (icmp_reply->type == ICMP_ECHOREPLY && ntohs(icmp_reply->un.echo.id) == (getpid() & 0xFFFF)) {
            printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth->h_source[0], eth->h_source[1], eth->h_source[2],
                eth->h_source[3], eth->h_source[4], eth->h_source[5]);
            found = true;
        }
    }
    if (!found) {
        std::cerr << "ICMP Echo Reply not received or no MAC found" << std::endl;
    }
    close(eth_sock);

    close(sock);
    return 0;
}
