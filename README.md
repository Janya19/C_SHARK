# C-Shark

C-Shark is a lightweight, custom-built Network Packet Analyzer (sniffer) written in C. Utilizing the robust `libpcap` library, it captures and decodes live network traffic operating across multiple OSI layers. It provides a highly interactive terminal UI to filter packets, inspect protocol headers, and display raw payload data.

## Key Features

### 1. Multi-Layer Protocol Parsing
C-Shark dissects packets as they traverse the OSI model, printing detailed header information for each layer:
- **Layer 2 (Data Link):** Ethernet (Source/Destination MAC Addresses, EtherType).
- **Layer 3 (Network):** 
  - **IPv4 & IPv6:** Extracts Source/Destination IPs, TTL/Hop Limits, Protocol/Next Header identifiers, and header lengths.
  - **ARP:** Parses ARP Requests/Replies, extracting Sender/Target MAC and IP mappings.
- **Layer 4 (Transport):**
  - **TCP:** Identifies common ports (HTTP, HTTPS, DNS), Sequence/Acknowledgment numbers, Window Size, Checksum, and specific Control Flags (SYN, ACK, FIN, PSH, RST, URG).
  - **UDP:** Extracts Source/Destination Ports, Payload Length, and Checksum.
- **Layer 7 (Application):** Performs raw hexdump + ASCII conversions to display up to the first 64 bytes of printable payload data.

### 2. Live Capture & BPF Filtering
Monitor traffic on any available network interface (e.g., `eth0`, `wlan0`, `lo`). C-Shark allows users to inject Berkeley Packet Filters (BPF) natively before initiating the capture loop:
- Sniff **All Packets** across the selected interface.
- Apply strict **Filters** to isolate specific traffic (e.g., TCP, UDP, ARP, DNS/Port 53, HTTP/Port 80, HTTPS/Port 443).

### 3. Session Management & Inspection
C-Shark caches up to 10,000 packets per live session into memory dynamically.
- Gracefully stop a live capture using `Ctrl+C`.
- **Inspect Last Session:** Re-examine deeply detailed views of any previously captured packet by its ID using the cached network payloads without needing to re-sniff. Sessions are automatically purged upon new captures to prevent memory leaks.

## Tech Stack & Architecture
- **Language:** C
- **Libraries Used:** 
  - `libpcap` (For low-level socket packet capturing, BPF compilation, and interface polling)
  - standard POSIX networking headers (`<netinet/ip.h>`, `<netinet/tcp.h>`, `<net/ethernet.h>`, `<arpa/inet.h>`)

## Compilation & Usage

### Prerequisites
You must have the `libpcap-dev` library installed on your system to compile and run the packet sniffer.
```bash
# Ubuntu / Debian
sudo apt-get install libpcap-dev
```

### Build and Run
Use the provided `Makefile` to compile the binary:

```bash
# Compile the executable
make

# Run the sniffer (Requires root privileges to bind to network interfaces)
sudo ./cshark
```

*(Optional): To capture packets and simultaneously save the terminal output to a text file for reporting, use `tee`:*
```bash
sudo ./cshark | tee output.txt
```
