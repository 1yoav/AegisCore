#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <cstdlib>

namespace fs = std::filesystem;

struct AnalysisTask {
    std::string name;
    std::string command;
    fs::path path;
};

bool executeTask(const AnalysisTask& task) {
    std::cout << "[*] Starting: " << task.name << "..." << std::endl;

    // Ensure the path exists before attempting to run it
    if (!fs::exists(task.path)) {
        std::cerr << " [!] Error: Path does not exist -> " << task.path << std::endl;
        return false;
    }

    // Construct the full command string
    std::string fullCommand = task.command + " \"" + task.path.string() + "\"";

    // Execute and capture the exit code
    int result = std::system(fullCommand.c_str());

    if (result == 0) {
        std::cout << " [+] " << task.name << " completed successfully." << std::endl;
        return true;
    }
    else {
        std::cerr << " [!] " << task.name << " failed with exit code: " << result << std::endl;
        return false;
    }
}

int main() {
    const fs::path baseDir = "C:/Users/Cyber_User/Desktop/magshimim/aegiscore-av";

    std::vector<AnalysisTask> pipeline = {
        //{"Deep Analysis", "python", baseDir / "deep_analysis/main.py"},
        //{"Signature Scan", "", baseDir / "aegiscore (static scans)/x64/Debug/aegiscore (static scans).exe"},
        {"Hooking Engine", "", baseDir / "MainProcces/x64/Debug/MainProcces.exe"}
        //{"TLS Cert Check", "python3", baseDir / "deep_analysis/tlscheck2.py"}
    };

    for (const auto& task : pipeline) {
        if (!executeTask(task)) {
            std::cerr << "[-] Critical failure in pipeline. Aborting." << std::endl;
            return EXIT_FAILURE;
        }
    }

    std::cout << "\n[SUCCESS] All security analysis modules completed." << std::endl;
    return EXIT_SUCCESS;
}