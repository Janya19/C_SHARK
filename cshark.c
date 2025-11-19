#include <stdio.h>
#include <netinet/icmp6.h>
#include <stdlib.h>
#include <pcap.h>
#include <signal.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/ip6.h> // For IPv6 header
#include <netinet/if_ether.h>
#include <net/if_arp.h>  // For ARP header
#include <sys/types.h>

// --- Packet Storage ---
#define MAX_PACKETS 10000
struct SavedPacket {
    struct pcap_pkthdr header;
    u_char *data;
};
struct SavedPacket saved_packets[MAX_PACKETS];
int saved_packet_count = 0;

// --- Global variables for capture session ---
pcap_t *handle;
int packet_count = 0;

// --- Forward Declarations ---
void print_mac_address(const u_char *mac);
void handle_ip_packet(const u_char *packet);
void handle_tcp_packet(const u_char *packet, int size);
void handle_udp_packet(const u_char *packet, int size);
void print_payload(const u_char *payload, int len);
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);

// --- Helper function to print a MAC address ---
void print_mac_address(const u_char *mac) {
    for (int i = 0; i < 6; ++i) {
        printf("%02x", mac[i]);
        if (i < 5) printf(":");
    }
}

// --- Function to print the Layer 7 payload ---
void print_payload(const u_char *payload, int len) {
    printf("L7 (Payload): %d bytes\n", len);
    printf("Data (first 64 bytes):\n");

    int len_to_print = (len < 64) ? len : 64;
    
    for (int i = 0; i < len_to_print; i++) {
        printf("%02x ", payload[i]);
        if ((i + 1) % 16 == 0 || i == len_to_print - 1) {
            if ((i + 1) % 16 != 0) {
                for (int j = 0; j < 16 - ((i + 1) % 16); j++) {
                    printf("   ");
                }
            }
            printf(" ");
            int start = i - (i % 16);
            for (int j = start; j <= i; j++) {
                printf("%c", isprint(payload[j]) ? payload[j] : '.');
            }
            printf("\n");
        }
    }
}

// NEW: Function to handle Layer 3 (IPv6) Packets
void handle_ipv6_packet(const u_char *packet) {
    struct ip6_hdr *ip6_header = (struct ip6_hdr *) packet;
    char src_ip_str[INET6_ADDRSTRLEN];
    char dst_ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip_str, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip_str, INET6_ADDRSTRLEN);
    
    printf("L3 (IPv6): Src IP: %s\n", src_ip_str);
    printf("           Dst IP: %s\n", dst_ip_str);
    printf("           Next Header: ");

    u_char next_header = ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;

    switch (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
        case IPPROTO_TCP: printf("TCP (%d)", IPPROTO_TCP); break;
        case IPPROTO_UDP: printf("UDP (%d)", IPPROTO_UDP); break;
        case IPPROTO_ICMPV6: printf("ICMPv6 (%d)", IPPROTO_ICMPV6); break;
        default: printf("Unknown (%d)", ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt); break;
    }
    printf(" | Hop Limit: %d\n", ip6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim);
    // --- ADD THIS SWITCH STATEMENT ---
    // Move to the next layer (L4)
    const u_char *next_layer_packet = packet + sizeof(struct ip6_hdr);
    // The payload length for L4 is in the IPv6 header
    int payload_len = ntohs(ip6_header->ip6_plen);

    switch (next_header) {
        case IPPROTO_TCP:
            handle_tcp_packet(next_layer_packet, payload_len);
            break;
        case IPPROTO_UDP:
            handle_udp_packet(next_layer_packet, payload_len);
            break;
    }
}

// NEW: Function to handle Layer 3 (ARP) Packets
void handle_arp_packet(const u_char *packet) {
    struct arphdr *arp_header = (struct arphdr *) packet;
    // The actual addresses are located immediately after the arphdr.
    // The ether_arp struct is designed for this.
    struct ether_arp *arp_payload = (struct ether_arp *) packet;

    printf("L3 (ARP): Operation: %s (%d)\n", 
           (ntohs(arp_header->ar_op) == ARPOP_REQUEST) ? "Request" : "Reply", 
           ntohs(arp_header->ar_op));
           
    char sender_ip_str[INET_ADDRSTRLEN];
    char target_ip_str[INET_ADDRSTRLEN];
    // The IP addresses are stored as byte arrays, so we pass their address
    inet_ntop(AF_INET, arp_payload->arp_spa, sender_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_payload->arp_tpa, target_ip_str, INET_ADDRSTRLEN);

    printf("           Sender IP: %s | Target IP: %s\n", sender_ip_str, target_ip_str);
    printf("           Sender MAC: ");
    print_mac_address(arp_payload->arp_sha);
    printf(" | Target MAC: ");
    print_mac_address(arp_payload->arp_tha);
    printf("\n");
}

// --- Function to handle Layer 4 (TCP) segment ---
void handle_tcp_packet(const u_char *packet, int size) {
    struct tcphdr *tcp_header = (struct tcphdr *) packet;
    int tcp_header_len = tcp_header->th_off * 4;

    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);

    printf("L4 (TCP): Src Port: %d", src_port);
    if (src_port == 80 || dst_port == 80) printf(" (HTTP)");
    if (src_port == 443 || dst_port == 443) printf(" (HTTPS)");
    if (src_port == 53 || dst_port == 53) printf(" (DNS)");

    printf(" | Dst Port: %d", dst_port);
    if (src_port == 80 || dst_port == 80) printf(" (HTTP)");
    if (src_port == 443 || dst_port == 443) printf(" (HTTPS)");
    if (src_port == 53 || dst_port == 53) printf(" (DNS)");
    printf("\n");

    printf("           Seq: %u | Ack: %u | Header Length: %d bytes\n",
           ntohl(tcp_header->th_seq), ntohl(tcp_header->th_ack), tcp_header_len);
    printf("           Flags: [");
    if (tcp_header->th_flags & TH_URG) printf("URG,");
    if (tcp_header->th_flags & TH_ACK) printf("ACK,");
    if (tcp_header->th_flags & TH_PUSH) printf("PSH,");
    if (tcp_header->th_flags & TH_RST) printf("RST,");
    if (tcp_header->th_flags & TH_SYN) printf("SYN,");
    if (tcp_header->th_flags & TH_FIN) printf("FIN,");
    printf("] | Window: %d | Checksum: 0x%x\n",
           ntohs(tcp_header->th_win), ntohs(tcp_header->th_sum));

    const u_char *payload = packet + tcp_header_len;
    int payload_len = size - tcp_header_len;
    if (payload_len > 0) {
        print_payload(payload, payload_len);
    }
}


// --- Function to handle Layer 4 (UDP) segment ---
void handle_udp_packet(const u_char *packet, int size) {
    struct udphdr *udp_header = (struct udphdr *) packet;
    int udp_header_len = 8;

    uint16_t src_port = ntohs(udp_header->uh_sport);
    uint16_t dst_port = ntohs(udp_header->uh_dport);
    
    printf("L4 (UDP): Src Port: %d", src_port);
    if (src_port == 53 || dst_port == 53) printf(" (DNS)");
    
    printf(" | Dst Port: %d", dst_port);
    if (src_port == 53 || dst_port == 53) printf(" (DNS)");

    printf(" | Length: %d | Checksum: 0x%x\n", 
           ntohs(udp_header->uh_ulen), ntohs(udp_header->uh_sum));

    const u_char *payload = packet + udp_header_len;
    int payload_len = size - udp_header_len;
    if (payload_len > 0) {
        print_payload(payload, payload_len);
    }
}
// --- Function to handle Layer 3 (IPv4) Packets ---
void handle_ip_packet(const u_char *packet) {
    struct ip *ip_header = (struct ip *) packet;
    int ip_header_len = ip_header->ip_hl * 4;

    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);

    printf("L3 (IPv4): Src IP: %s | Dst IP: %s\n", src_ip_str, dst_ip_str);
    printf("           Protocol: ");
    switch (ip_header->ip_p) {
        case IPPROTO_TCP: printf("TCP (%d)", ip_header->ip_p); break;
        case IPPROTO_UDP: printf("UDP (%d)", ip_header->ip_p); break;
        case IPPROTO_ICMP: printf("ICMP (%d)", ip_header->ip_p); break;
        default: printf("Unknown (%d)", ip_header->ip_p); break;
    }
    printf(" | TTL: %d | ID: 0x%x | Total Length: %d | Header Length: %d bytes\n",
           ip_header->ip_ttl, ntohs(ip_header->ip_id), ntohs(ip_header->ip_len), ip_header_len);

    // This part stays the same
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            handle_tcp_packet(packet + ip_header_len, ntohs(ip_header->ip_len) - ip_header_len);
            break;
        case IPPROTO_UDP:
            handle_udp_packet(packet + ip_header_len, ntohs(ip_header->ip_len) - ip_header_len);
            break;
    }
}

// --- Main Callback: called for every packet, saves and prints ---
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Only save the packet if it's a live capture (user_data will be NULL)
    // This prevents re-saving during inspection
    if (user_data == NULL && saved_packet_count < MAX_PACKETS) {
        saved_packets[saved_packet_count].header = *pkthdr;
        saved_packets[saved_packet_count].data = malloc(pkthdr->caplen);
        if (saved_packets[saved_packet_count].data != NULL) {
            memcpy(saved_packets[saved_packet_count].data, packet, pkthdr->caplen);
            saved_packet_count++;
        }
    }
    
    packet_count++;
    
    printf("-----------------------------------------\n");
    printf("Packet #%d | Timestamp: %ld.%06ld | Length: %d bytes\n", 
           packet_count, pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, pkthdr->len);

    struct ether_header *eth_header = (struct ether_header *) packet;
    printf("L2 (Ethernet): Dst MAC: ");
    print_mac_address(eth_header->ether_dhost);
    printf(" | Src MAC: ");
    print_mac_address(eth_header->ether_shost);
    
    uint16_t ether_type = ntohs(eth_header->ether_type);
    
    printf(" | EtherType: ");
    switch (ether_type) {
        case ETHERTYPE_IP:
            printf("IPv4 (0x%04x)\n", ether_type);
            handle_ip_packet(packet + sizeof(struct ether_header));
            break;
        case ETHERTYPE_ARP:
            printf("ARP (0x%04x)\n", ether_type);
            // UPDATED: Call the new ARP handler
            handle_arp_packet(packet + sizeof(struct ether_header));
            break;
        case ETHERTYPE_IPV6:
            printf("IPv6 (0x%04x)\n", ether_type);
            // UPDATED: Call the new IPv6 handler
            handle_ipv6_packet(packet + sizeof(struct ether_header));
            break;
        default:
            printf("Unknown (0x%04x)\n", ether_type);
            break;
    }
}

// --- Function to free all saved packets ---
void free_saved_packets() {
    for (int i = 0; i < saved_packet_count; i++) {
        free(saved_packets[i].data);
        saved_packets[i].data = NULL;
    }
    saved_packet_count = 0;
    printf("\n[INFO] Previous session cleared.\n");
}

// --- Function to handle packet inspection ---
void inspect_packets() {
    if (saved_packet_count == 0) {
        printf("\nNo session has been captured yet. Please sniff some packets first.\n");
        return;
    }

    printf("\n--- Last Captured Session (%d packets) ---\n", saved_packet_count);
    for(int i=0; i < saved_packet_count; i++){
        printf("  Packet #%d: Length %d\n", i + 1, saved_packets[i].header.len);
    }
    printf("Enter Packet ID to inspect (1-%d): ", saved_packet_count);
    fflush(stdout);
    
    int inspect_id;
    // scanf("%d", &inspect_id);
    if (scanf(" %d", &inspect_id) == EOF) {
        printf("\n[INFO] Ctrl+D detected. Exiting.\n");
        exit(0);
    }

    if (inspect_id < 1 || inspect_id > saved_packet_count) {
        printf("\nInvalid Packet ID.\n");
        return;
    }
    
    // We re-use the main handler to print details, but pass non-NULL user_data
    // to prevent it from re-saving the packet we're inspecting.
    struct pcap_pkthdr *pkthdr = &saved_packets[inspect_id - 1].header;
    const u_char *packet_data = saved_packets[inspect_id - 1].data;
    
    int temp_count = packet_count;
    packet_count = inspect_id - 1; 

    printf("\n>>> Inspecting Packet #%d <<<\n", inspect_id);
    packet_handler((u_char*)1, pkthdr, packet_data); // Pass a non-NULL user_data
    
    packet_count = temp_count;
}

// --- Signal handler for Ctrl+C ---
void signal_handler(int signum) {
    if (handle != NULL) {
        printf("\nCapture stopped.\n");
        pcap_breakloop(handle);
    }
}

// --- UI Functions ---
void print_menu() {
    printf("\n[C-Shark] What's next?\n\n");
    printf("1. Start Sniffing (All Packets)\n");
    printf("2. Start Sniffing (With Filters)\n");
    printf("3. Inspect Last Session\n");
    printf("4. Exit C-Shark\n");
    printf("\nEnter your choice: ");
    fflush(stdout);
}

int main() {
    pcap_if_t *all_devs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 1;
    int choice;
    char *selected_device;

    printf("[C-Shark] The Command-Line Packet Predator\n");
    printf("==============================================\n");
    printf("[C-Shark] Searching for available interfaces... ");

    if (pcap_findalldevs(&all_devs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }
    
    printf("Found!\n\n");

    for (dev = all_devs; dev != NULL; dev = dev->next) {
        printf("%d. %s", i++, dev->name);
        if (dev->description) {
            printf(" (%s)\n", dev->description);
        } else {
            printf(" (No description available)\n");
        }
    }
    
    printf("\nSelect an interface to sniff (1-%d): ", i - 1);
    fflush(stdout); 
    // scanf("%d", &choice);
    if (scanf(" %d", &choice) == EOF) {
    printf("\n[INFO] Ctrl+D detected. Exiting.\n");
    exit(0);
    }

    dev = all_devs;
    for (int j = 1; j < choice && dev != NULL; j++) {
        dev = dev->next;
    }

    if (dev == NULL) {
        fprintf(stderr, "Invalid selection. Please choose a number from the list.\n");
        pcap_freealldevs(all_devs);
        return 1;
    }

    selected_device = strdup(dev->name);
    pcap_freealldevs(all_devs);
    printf("\n[C-Shark] Interface '%s' selected.\n", selected_device);
    
    int menu_choice = 0;
    while (menu_choice != 4) {
        print_menu();
        // scanf("%d", &menu_choice);
        if (scanf(" %d", &menu_choice) == EOF) {
            printf("\n[INFO] Ctrl+D detected. Exiting.\n");
            break; // Break will exit the while loop
        }
        
        char filter_str[100] = ""; 

        switch (menu_choice) {
            case 1:
                printf("\n>>> Starting to sniff all packets... (Press Ctrl+C to stop)\n");
                break;
            case 2:
                printf("\n--- Filter Options ---\n");
                printf("1. TCP\n2. UDP\n3. ARP\n4. DNS\n5. HTTP\n6. HTTPS\n");
                printf("Enter filter choice: ");
                fflush(stdout);
                int filter_choice;
                // scanf("%d", &filter_choice);
                if (scanf(" %d", &filter_choice) == EOF) {
                    printf("\n[INFO] Ctrl+D detected. Exiting.\n");
                    exit(0);
                }
                
                switch(filter_choice) {
                    case 1: strcpy(filter_str, "tcp"); break;
                    case 2: strcpy(filter_str, "udp"); break;
                    case 3: strcpy(filter_str, "arp"); break;
                    case 4: strcpy(filter_str, "udp and port 53"); break;
                    case 5: strcpy(filter_str, "tcp and port 80"); break;
                    case 6: strcpy(filter_str, "tcp and port 443"); break;
                    default: printf("Invalid filter choice.\n"); continue;
                }
                printf("\n>>> Starting to sniff with filter: \"%s\" (Press Ctrl+C to stop)\n", filter_str);
                break;
            case 3:
                inspect_packets();
                continue; 
            case 4:
                printf("\nExiting C-Shark. Goodbye!\n");
                continue;
            default:
                printf("\nInvalid choice. Please try again.\n");
                continue;
        }

        if (menu_choice == 1 || menu_choice == 2) {
            if (saved_packet_count > 0) {
                free_saved_packets();
            }

            handle = pcap_open_live(selected_device, BUFSIZ, 1, 1000, errbuf);
            if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", selected_device, errbuf);
                continue;
            }

            if (strlen(filter_str) > 0) {
                struct bpf_program fp;
                if (pcap_compile(handle, &fp, filter_str, 0, PCAP_NETMASK_UNKNOWN) == -1) {
                    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_str, pcap_geterr(handle));
                    continue;
                }
                if (pcap_setfilter(handle, &fp) == -1) {
                    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_str, pcap_geterr(handle));
                    continue;
                }
                pcap_freecode(&fp);
            }
            
            signal(SIGINT, signal_handler);
            packet_count = 0;
            pcap_loop(handle, -1, packet_handler, NULL);
            
            pcap_close(handle);
            handle = NULL;
        }
    }

    free_saved_packets();
    free(selected_device);
    return 0;
}