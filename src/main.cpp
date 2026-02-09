/**
 * @file main.cpp
 * @brief Antivirus CLI entry point
 * 
 * Provides command-line interface for the antivirus engine.
 */

#include "antivirus/core/Engine.hpp"
#include "antivirus/scanner/FileScanner.hpp"
#include "antivirus/threading/ThreadPool.hpp"
#include "antivirus/detection/SignatureDatabase.hpp"
#include "antivirus/detection/HashEngine.hpp"
#include "antivirus/detection/PatternMatcher.hpp"
#include "antivirus/quarantine/QuarantineManager.hpp"
#include "antivirus/config/ConfigManager.hpp"
#include "antivirus/logging/Logger.hpp"
#include "antivirus/gpu/GpuComputeFactory.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace av = antivirus;

void PrintUsage(const char* programName) {
    std::cout << "High-Performance Antivirus Scanner\n"
              << "===================================\n\n"
              << "Usage: " << programName << " [command] [options]\n\n"
              << "Commands:\n"
              << "  scan <path>      Scan specified path\n"
              << "  quick            Quick scan (common malware locations)\n"
              << "  full             Full system scan\n"
              << "  quarantine       Manage quarantined files\n"
              << "    list           List quarantined files\n"
              << "    restore <id>   Restore file by ID\n"
              << "    delete <id>    Delete file by ID\n"
              << "  status           Show engine status\n"
              << "  help             Show this help\n\n"
              << "Options:\n"
              << "  -t, --threads N  Number of threads to use\n"
              << "  -v, --verbose    Verbose output\n"
              << "  -q, --quiet      Quiet mode (errors only)\n"
              << std::endl;
}

void PrintProgress(const av::ScanStatistics& stats) {
    std::cout << "\r[" 
              << stats.scannedFiles.load() << " scanned | "
              << stats.infectedFiles.load() << " infected | "
              << (stats.scanRate()) << " files/sec]" 
              << std::flush;
}

class AntivirusApp {
public:
    AntivirusApp() {
        // Initialize components
        m_logger = av::CreateConsoleLogger();
        m_config = std::make_shared<av::ConfigManager>("config.json");
        m_threadPool = av::CreateOptimalThreadPool();
        m_scanner = std::make_shared<av::FileScanner>(m_logger);
        m_signatureDb = std::make_shared<av::SignatureDatabase>(m_logger);
        m_hashEngine = std::make_shared<av::HashEngine>();
        m_patternMatcher = std::make_shared<av::PatternMatcher>();
        m_quarantine = std::make_shared<av::QuarantineManager>(
            m_config->GetQuarantinePath(), m_logger
        );
        m_gpuCompute = av::GpuComputeFactory::CreateCpuFallback(m_logger);
        
        // Build engine
        m_engine = av::EngineBuilder()
            .WithScanner(m_scanner)
            .WithThreadPool(m_threadPool)
            .WithSignatureDatabase(m_signatureDb)
            .WithHashEngine(m_hashEngine)
            .WithPatternMatcher(m_patternMatcher)
            .WithQuarantine(m_quarantine)
            .WithLogger(m_logger)
            .WithConfig(m_config)
            .WithGpuCompute(m_gpuCompute)
            .Build();
        
        // Set up callbacks
        m_engine->SetThreatCallback([this](const av::FileInfo& file, const av::ThreatInfo& threat) {
            std::cout << "\n⚠️  THREAT DETECTED: " << threat.threatName 
                      << " in " << file.path.string() << std::endl;
        });
        
        m_engine->SetProgressCallback([](const av::ScanStatistics& stats) {
            PrintProgress(stats);
        });
    }
    
    bool Initialize() {
        return m_engine->Initialize();
    }
    
    int RunQuickScan() {
        std::cout << "Starting quick scan...\n";
        
        if (!m_engine->StartQuickScan()) {
            std::cerr << "Failed to start scan\n";
            return 1;
        }
        
        PrintResults();
        return m_engine->GetStatistics().infectedFiles.load() > 0 ? 1 : 0;
    }
    
    int RunFullScan() {
        std::cout << "Starting full system scan...\n";
        std::cout << "This may take a while.\n\n";
        
        if (!m_engine->StartFullScan()) {
            std::cerr << "Failed to start scan\n";
            return 1;
        }
        
        PrintResults();
        return m_engine->GetStatistics().infectedFiles.load() > 0 ? 1 : 0;
    }
    
    int RunCustomScan(const std::vector<av::FilePath>& paths) {
        std::cout << "Starting scan of " << paths.size() << " path(s)...\n";
        
        if (!m_engine->StartCustomScan(paths)) {
            std::cerr << "Failed to start scan\n";
            return 1;
        }
        
        PrintResults();
        return m_engine->GetStatistics().infectedFiles.load() > 0 ? 1 : 0;
    }
    
    void ListQuarantine() {
        auto entries = m_quarantine->GetEntries();
        
        if (entries.empty()) {
            std::cout << "No quarantined files.\n";
            return;
        }
        
        std::cout << "Quarantined files:\n";
        std::cout << std::string(60, '-') << '\n';
        
        for (const auto& entry : entries) {
            std::cout << "ID: " << entry.id.substr(0, 8) << "...\n"
                      << "  Original: " << entry.originalPath.string() << '\n'
                      << "  Threat: " << entry.threatName << '\n'
                      << "  Size: " << entry.originalSize << " bytes\n\n";
        }
    }
    
    bool RestoreQuarantine(const std::string& id) {
        return m_quarantine->Restore(id);
    }
    
    bool DeleteQuarantine(const std::string& id) {
        return m_quarantine->Delete(id);
    }
    
    void ShowStatus() {
        std::cout << "Antivirus Engine Status\n";
        std::cout << std::string(40, '=') << '\n';
        std::cout << "Ready: " << (m_engine->IsReady() ? "Yes" : "No") << '\n';
        std::cout << "Signatures loaded: " << m_engine->GetSignatureCount() << '\n';
        std::cout << "Thread pool threads: " << m_threadPool->GetThreadCount() << '\n';
        std::cout << "Quarantined files: " << m_quarantine->GetEntryCount() << '\n';
        std::cout << "Quarantine size: " << m_quarantine->GetTotalSize() << " bytes\n";
    }

private:
    void PrintResults() {
        auto stats = m_engine->GetStatistics();
        
        std::cout << "\n\n";
        std::cout << "Scan Complete\n";
        std::cout << std::string(40, '=') << '\n';
        std::cout << "Total files: " << stats.totalFiles.load() << '\n';
        std::cout << "Scanned: " << stats.scannedFiles.load() << '\n';
        std::cout << "Skipped: " << stats.skippedFiles.load() << '\n';
        std::cout << "Infected: " << stats.infectedFiles.load() << '\n';
        std::cout << "Quarantined: " << stats.quarantinedFiles.load() << '\n';
        std::cout << "Errors: " << stats.errorCount.load() << '\n';
        std::cout << "Duration: " << stats.elapsed().count() << " ms\n";
        std::cout << "Scan rate: " << stats.scanRate() << " files/sec\n";
    }
    
    std::shared_ptr<av::ILogger> m_logger;
    std::shared_ptr<av::IConfigManager> m_config;
    std::shared_ptr<av::IThreadPool> m_threadPool;
    std::shared_ptr<av::IFileScanner> m_scanner;
    std::shared_ptr<av::SignatureDatabase> m_signatureDb;
    std::shared_ptr<av::HashEngine> m_hashEngine;
    std::shared_ptr<av::PatternMatcher> m_patternMatcher;
    std::shared_ptr<av::IQuarantineManager> m_quarantine;
    std::shared_ptr<av::IGpuCompute> m_gpuCompute;
    std::unique_ptr<av::Engine> m_engine;
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    std::string command = argv[1];
    
    try {
        AntivirusApp app;
        
        if (!app.Initialize()) {
            std::cerr << "Failed to initialize antivirus engine\n";
            return 1;
        }
        
        if (command == "quick") {
            return app.RunQuickScan();
        }
        else if (command == "full") {
            return app.RunFullScan();
        }
        else if (command == "scan" && argc >= 3) {
            std::vector<av::FilePath> paths;
            for (int i = 2; i < argc; ++i) {
                paths.emplace_back(argv[i]);
            }
            return app.RunCustomScan(paths);
        }
        else if (command == "quarantine") {
            if (argc >= 3) {
                std::string subcommand = argv[2];
                if (subcommand == "list") {
                    app.ListQuarantine();
                }
                else if (subcommand == "restore" && argc >= 4) {
                    if (app.RestoreQuarantine(argv[3])) {
                        std::cout << "File restored successfully\n";
                    } else {
                        std::cerr << "Failed to restore file\n";
                        return 1;
                    }
                }
                else if (subcommand == "delete" && argc >= 4) {
                    if (app.DeleteQuarantine(argv[3])) {
                        std::cout << "File deleted successfully\n";
                    } else {
                        std::cerr << "Failed to delete file\n";
                        return 1;
                    }
                }
            } else {
                app.ListQuarantine();
            }
        }
        else if (command == "status") {
            app.ShowStatus();
        }
        else if (command == "help" || command == "-h" || command == "--help") {
            PrintUsage(argv[0]);
        }
        else {
            std::cerr << "Unknown command: " << command << '\n';
            PrintUsage(argv[0]);
            return 1;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
