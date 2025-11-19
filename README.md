How to run:
    make clean
    sudo ./cshark
//if you run it using sudo ./cshark | tee output.txt, all terminal output will also be saved to output.txt file

Testing:
- **Terminal 1** → run `cshark`  
- **Terminal 2** → generate traffic

---

### 1. Setup

**Terminal 1:**
```bash
make
sudo ./cshark
```
Select the **loopback interface** (`lo` or `lo0`).

**Terminal 2:** keep ready for commands below.

---

### 2. Test Common Protocols

Start sniffing **(All Packets)** in Terminal 1, then run these:

**ICMP (ping):**
```bash
ping 127.0.0.1 -c 3
```
→ Should show IPv4 + ICMP packets with `127.0.0.1` as src/dst.

**UDP (DNS):**
```bash
dig google.com
```
→ Look for UDP packets to port 53 with “google” in payload.

**TCP (HTTP):**
```bash
curl -s http://example.com > /dev/null
```
→ You should see the 3-way handshake (SYN, SYN-ACK, ACK) and the HTTP GET request.

---

### 3. Test ARP

Loopback doesn’t use ARP, so restart and pick your **main interface** (e.g. `wlan0`, `eth0`):

```bash
ip route | grep default
sudo arping -c 1 <router_ip>
```
→ Should capture ARP request with proper MAC/IP info.

---

### 4. Test Filters

Restart sniffing **(With Filters)** and pick **DNS** filter:

```bash
ping 127.0.0.1 -c 1   # shouldn't show
dig google.com        # should show
```
Repeat similarly for TCP using `curl`.

---

### 5. Inspect Sessions

Run a short capture (e.g. ping), stop with `Ctrl+C`, then choose **Inspect Last Session**.

→ Should list packets and show details for selected IDs.  
Start a new session to confirm old packets are cleared.

---
