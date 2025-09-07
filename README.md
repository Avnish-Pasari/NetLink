# 🖧 NetLink – Custom Network Router

A modular **Network Router and TCP/IP Stack** implemented in **C++**.  
The project builds a simplified yet fully functional link-layer interface and router supporting Ethernet, ARP, IPv4, and routing with longest-prefix-match.

---

## 📖 About the Project

This project simulates the core functionality of a real network router:

- A **Network Interface** that connects the Internet layer (IPv4) to the Link layer (Ethernet).
- Implements **ARP resolution** with dynamic caching and expiration timers.
- Encapsulates IPv4 datagrams into Ethernet frames, queues packets, and retries unresolved addresses.
- Handles incoming Ethernet frames, delivering IPv4 packets up the stack or responding to ARP requests.
- A **Router** that forwards packets across multiple interfaces using **longest-prefix-match routing**.

The system passes an automated test suite simulating real Ethernet/IP networking scenarios.

---

## ⚙️ Features

### Network Interface
- **IPv4 Datagram Encapsulation**: Wraps IP packets into Ethernet frames.
- **ARP Resolution**: Crafts ARP requests/replies and maintains an ARP cache with TTLs (5s for pending, 30s for resolved).
- **Packet Queuing**: Buffers datagrams while waiting on ARP replies.
- **Frame Reception**:
  - For IPv4: parses and delivers datagrams.
  - For ARP: updates ARP cache and responds if queried for its IP.

### Router
- **Multiple Interfaces**: Supports multiple `AsyncNetworkInterface` instances.
- **Routing Table**:
  - Prefix-based rules (`route_prefix`, `prefix_length`).
  - Supports direct delivery (no next hop) or forwarding via a gateway.
- **Longest-Prefix Match**: Chooses the most specific route for each packet.
- **TTL Handling**: Drops expired datagrams (TTL ≤ 1) and decrements TTL otherwise.

---

## 🛠️ Tech Stack

- **Language**: C++17
- **Core Concepts**: TCP/IP stack, ARP, Ethernet, Routing
- **Design Principles**: Modular, clean, and tested code
- **Environment**: Linux
- **Build System**: CMake

---

## 📂 Running the Project

To set up the build system: `cmake -S . -B build`

To compile: `cmake --build build`

To run tests: `cmake --build build --target pa1`

