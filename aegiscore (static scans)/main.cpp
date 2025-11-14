// packet filtering demo
// ==================== main.cpp ====================
#include "WFPEngine.h"
#include "PacketLogger.h"
#include "FilterRule.h"
#include <iostream>
#include <memory>
#include <thread>
#include <chrono>
#include <vector>

int main() {
    std::cout << "==================================" << std::endl;
    std::cout << "  WFP Network Packet Scanner" << std::endl;
    std::cout << "  Antivirus Network Monitor" << std::endl;
    std::cout << "==================================" << std::endl;
    std::cout << std::endl;

    // Initialize logger
    auto logger = std::make_shared<PacketLogger>("wfp_monitor.log", true);

    // Initialize WFP engine
    WFPEngine wfpEngine(logger);

    if (!wfpEngine.Initialize()) {
        logger->LogError("Failed to initialize WFP engine. Run as Administrator!");
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }

    // Add filters
    logger->LogInfo("Adding network filters...");

    std::vector<FilterRule> rules = {
        FilterRule("8.8.8.8", FilterType::BLOCK_IP, "Block Google DNS"),
        FilterRule("8.8.4.4", FilterType::BLOCK_IP, "Block Google DNS Secondary"),
        FilterRule(69, FilterType::BLOCK_PORT, "Block TFTP (port 69)"),
        FilterRule(3333, FilterType::BLOCK_PORT, "Block Cryptomining (port 3333)"),
        FilterRule(4444, FilterType::BLOCK_PORT, "Block Cryptomining (port 4444)"),
        FilterRule(9999, FilterType::BLOCK_PORT, "Block Cryptomining (port 9999)")
    };

    for (const auto& rule : rules) {
        wfpEngine.AddFilter(rule);
    }

    std::cout << "\n==================================" << std::endl;
    std::cout << "Filters Active:" << std::endl;
    std::cout << "  - Blocking: 8.8.8.8, 8.8.4.4" << std::endl;
    std::cout << "  - Blocking ports: 69, 3333, 4444, 9999" << std::endl;
    std::cout << "==================================" << std::endl;
    std::cout << "\nMonitoring network traffic..." << std::endl;
    std::cout << "Try: ping 8.8.8.8 or browse to a site using port 69" << std::endl;
    std::cout << "\nPress Enter to stop monitoring..." << std::endl;

    // Wait for user input
    std::cin.get();

    // Cleanup
    logger->LogInfo("Shutting down...");
    wfpEngine.Shutdown();

    std::cout << "\nMonitoring stopped. Check wfp_monitor.log for details." << std::endl;
    return 0;
}

//#include <iostream>
//#include "SQLDatabase.h"
//
//int main(void)
//{
//	std::cout << "Welcome to AegisCore! Passive Scanner activated.\n\n";
//
//	std::cout << "INitializing databse...\n";
//
//	sqlite3* database = nullptr;
//	SQLDatabase db(database, "DATABASE");
//
//
//	return 0;
//}
