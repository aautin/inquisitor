# Inquisitor - ARP Spoofing Tool

## Demo

![DEMO](./demo.gif)

## Workflow Diagram

```mermaid
flowchart TD
    A[Start: Parse CLI Arguments] --> B[Initialize Network Interface]
    B --> C[Setup Packet Capture on eth0]
    C --> D[Create Spoofer Thread]
    D --> E[Start ARP Poisoning Loop]
    E --> F[Send Poisoned ARP Replies]
    F --> G[Monitor Network Traffic]
    G --> H{FTP Traffic Detected?}
    H -- Yes --> I[Extract FTP Commands/Files]
    H -- No --> J[Continue Monitoring]
    I --> J
    J --> K{Stop Signal Received?}
    K -- No --> F
    K -- Yes --> L[Restore ARP Tables]
    L --> M[Send Gratuitous ARP]
    M --> N[End]
```

- **Initialization Phase**: Parses source/target IP/MAC addresses and sets up packet capture interface.
- **ARP Poisoning Phase**: Continuously sends spoofed ARP replies to redirect traffic through the inquisitor.
- **Traffic Monitoring Phase**: Intercepts and analyzes network packets, specifically monitoring FTP file transfers.
- **Cleanup Phase**: On termination, restores original ARP tables to return network to normal state.

## Network Testing Environment

Three containers for network security testing:
- **Server** : FTP Server (PORT 21) with test files
- **Client** : Client machine for network operations  
- **Inquisitor** : ARP spoofing tool for man-in-the-middle attacks

## Requirements

- Docker & Docker Compose
- Linux environment with network capabilities