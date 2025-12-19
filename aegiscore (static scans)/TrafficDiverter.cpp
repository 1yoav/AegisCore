#include "TrafficDiverter.h"
#include "NetworkUtils.h"
#include "PipeClient.h"
#include <iostream>

#pragma comment(lib, "WinDivert.lib")

TrafficDiverter::TrafficDiverter(uint16_t port)
    : proxyPort(port), running(true) {
}

TrafficDiverter::~TrafficDiverter() {
    StopAll();
}

bool TrafficDiverter::StartDiverting(uint32_t pid) {
    // Build WinDivert filter for this PID
    std::string filter = "processId == " + std::to_string(pid) + " and tcp";

    // Open WinDivert handle
    HANDLE handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] WinDivert failed for PID " << pid << std::endl;
        return false;
    }

    // Store handle
    activeDiversions[pid] = handle;

    // Start worker thread
    divertThreads[pid] = std::thread(&TrafficDiverter::DivertWorker, this, pid, handle);

    std::cout << "[*] Started diverting PID " << pid << " to proxy port " << proxyPort << std::endl;
    return true;
}

bool TrafficDiverter::StopDiverting(uint32_t pid) {
    auto handleIt = activeDiversions.find(pid);
    if (handleIt == activeDiversions.end()) return false;

    // Close handle (this will cause DivertWorker to exit)
    WinDivertClose(handleIt->second);
    activeDiversions.erase(handleIt);

    // Wait for thread to finish
    auto threadIt = divertThreads.find(pid);
    if (threadIt != divertThreads.end()) {
        if (threadIt->second.joinable()) {
            threadIt->second.join();
        }
        divertThreads.erase(threadIt);
    }

    return true;
}

void TrafficDiverter::StopAll() {
    running = false;

    // Close all handles
    for (auto& pair : activeDiversions) {
        WinDivertClose(pair.second);
    }

    // Join all threads
    for (auto& pair : divertThreads) {
        if (pair.second.joinable()) {
            pair.second.join();
        }
    }

    activeDiversions.clear();
    divertThreads.clear();
}

std::string TrafficDiverter::MakeConnectionKey(uint32_t srcIP, uint16_t srcPort) {
    return std::to_string(srcIP) + ":" + std::to_string(srcPort);
}

void TrafficDiverter::DivertWorker(uint32_t pid, HANDLE handle) {
    char packet[65535];
    UINT packetLen;
    WINDIVERT_ADDRESS addr;

    PWINDIVERT_IPHDR ipHdr;
    PWINDIVERT_TCPHDR tcpHdr;

    while (running) {
        // Receive packet
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packetLen, &addr)) {
            // Handle closed or error - exit thread
            break;
        }

        // Parse packet
        WinDivertHelperParsePacket(
            packet,             // 1. pPacket
            packetLen,          // 2. packetLen
            &ipHdr,             // 3. ppIpHdr
            NULL,               // 4. ppIpv6Hdr
            NULL,               // 5. pProtocol
            NULL,               // 6. ppIcmpHdr
            NULL,               // 7. ppIcmpv6Hdr
            &tcpHdr,            // 8. ppTcpHdr
            NULL,               // 9. ppUdpHdr
            NULL,               // 10. ppData (Payload pointer)
            NULL,               // 11. pDataLen (Payload length)
            NULL,               // 12. ppNext (Next packet in batch)
            NULL                // 13. pNextLen (Next packet length)
        );

        if (!ipHdr || !tcpHdr) {
            // Not TCP, just forward it
            WinDivertSend(handle, packet, packetLen, NULL, &addr);
            continue;
        }

        if (addr.Outbound) {
            // === OUTBOUND: Malware ? Internet ===
            // Save original destination
            uint32_t origDestIP = ntohl(ipHdr->DstAddr);
            uint16_t origDestPort = ntohs(tcpHdr->DstPort);

            // Create connection key
            std::string connKey = MakeConnectionKey(
                ntohl(ipHdr->SrcAddr),
                ntohs(tcpHdr->SrcPort)
            );

            // Store original destination
            connectionMap[connKey] = { origDestIP, origDestPort };

            // Alert Python via pipe (only on first packet of connection)
            if (tcpHdr->Syn && !tcpHdr->Ack) {  // SYN packet
                std::string origIPStr = NetworkUtils::UInt32ToIPString(origDestIP);
                PipeClient::SendAlert(pid, "Diverted Process", origIPStr, origDestPort);
            }

            // Redirect to Python proxy: 127.0.0.1:8080
            ipHdr->DstAddr = htonl(0x7F000001);  // 127.0.0.1
            tcpHdr->DstPort = htons(proxyPort);

        }
        else {
            // === INBOUND: Proxy ? Malware ===
            // Restore original source to spoof the real C2 server

            std::string connKey = MakeConnectionKey(
                ntohl(ipHdr->DstAddr),  // Malware's IP
                ntohs(tcpHdr->DstPort)  // Malware's port
            );

            auto it = connectionMap.find(connKey);
            if (it != connectionMap.end()) {
                // Spoof source as the original C2 server
                ipHdr->SrcAddr = htonl(it->second.ip);
                tcpHdr->SrcPort = htons(it->second.port);
            }
        }

        // Recalculate checksums (CRITICAL!)
        WinDivertHelperCalcChecksums(packet, packetLen, &addr, 0);

        // Send modified packet back
        WinDivertSend(handle, packet, packetLen, NULL, &addr);
    }

    std::cout << "[*] Divert worker for PID " << pid << " exited" << std::endl;
}