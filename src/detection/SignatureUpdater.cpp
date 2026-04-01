/**
 * @file SignatureUpdater.cpp
 * @brief Online signature updater implementation
 * 
 * Uses Windows native WinHTTP for network operations.
 * Downloads from MalwareBazaar (abuse.ch) public API.
 */

#include "antivirus/detection/SignatureUpdater.hpp"
#include <fstream>
#include <sstream>
#include <unordered_set>

#ifdef _WIN32
    #include <Windows.h>
    #include <winhttp.h>
    #pragma comment(lib, "winhttp.lib")
#endif

namespace antivirus {

SignatureUpdater::SignatureUpdater(
    std::shared_ptr<ILogger> logger,
    std::filesystem::path signatureDir
)
    : m_logger(std::move(logger))
    , m_signatureDir(std::move(signatureDir))
{
}

SignatureUpdater::~SignatureUpdater() = default;

UpdateStats SignatureUpdater::UpdateFromMalwareBazaar(
    UpdateProgressCallback progressCallback
) {
    UpdateStats stats;
    
    m_logger->Info("Starting signature update from MalwareBazaar...");
    
    try {
        // Query MalwareBazaar for recent samples (last 24 hours)
        // API docs: https://bazaar.abuse.ch/api/
        std::string postData = "query=get_recent&selector=time&hours=24";
        
        m_logger->Info("Downloading latest threat intelligence...");
        auto response = HttpPost(
            "mb-api.abuse.ch",
            "/api/v1/",
            postData,
            "application/x-www-form-urlencoded"
        );
        
        stats.downloadedBytes = response.size();
        
        if (response.empty()) {
            stats.errorMessage = "Empty response from MalwareBazaar";
            m_logger->Error("Update failed: empty response");
            return stats;
        }
        
        if (progressCallback) {
            progressCallback(stats.downloadedBytes, stats.downloadedBytes);
        }
        
        m_logger->Info("Downloaded {} bytes, parsing...", stats.downloadedBytes);
        
        // Parse response and extract hashes
        auto newHashes = ParseMalwareBazaarResponse(response);
        m_logger->Info("Parsed {} new malware hashes", newHashes.size());
        
        // Merge into signature database
        stats.newSignatures = MergeSignatures(newHashes);
        stats.success = true;
        
        m_logger->Info("Signature update complete: {} new signatures added", 
            stats.newSignatures);
        
    } catch (const std::exception& e) {
        stats.errorMessage = e.what();
        stats.success = false;
        m_logger->Error("Signature update failed: {}", e.what());
    }
    
    return stats;
}

std::string SignatureUpdater::HttpPost(
    const std::string& host,
    const std::string& path,
    const std::string& postData,
    const std::string& contentType
) {
#ifdef _WIN32
    std::string result;
    
    // Convert to wide strings
    std::wstring wHost(host.begin(), host.end());
    std::wstring wPath(path.begin(), path.end());
    std::wstring wContentType(contentType.begin(), contentType.end());
    
    // Open WinHTTP session
    HINTERNET hSession = WinHttpOpen(
        L"AntiVirus-Updater/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    
    if (!hSession) {
        throw std::runtime_error("WinHttpOpen failed: " + std::to_string(GetLastError()));
    }
    
    // Connect to server
    HINTERNET hConnect = WinHttpConnect(
        hSession,
        wHost.c_str(),
        INTERNET_DEFAULT_HTTPS_PORT,
        0
    );
    
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("WinHttpConnect failed: " + std::to_string(GetLastError()));
    }
    
    // Create request
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        wPath.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );
    
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("WinHttpOpenRequest failed: " + std::to_string(GetLastError()));
    }
    
    // Set content type header
    std::wstring header = L"Content-Type: " + wContentType;
    WinHttpAddRequestHeaders(hRequest, header.c_str(), 
        static_cast<DWORD>(header.length()), WINHTTP_ADDREQ_FLAG_REPLACE);
    
    // Send request
    BOOL bResults = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        const_cast<char*>(postData.c_str()),
        static_cast<DWORD>(postData.size()),
        static_cast<DWORD>(postData.size()),
        0
    );
    
    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, nullptr);
    }
    
    if (bResults) {
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        
        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            if (dwSize == 0) break;
            
            std::vector<char> buffer(dwSize + 1, 0);
            if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) break;
            
            result.append(buffer.data(), dwDownloaded);
        } while (dwSize > 0);
    }
    
    // Cleanup
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    if (!bResults) {
        throw std::runtime_error("HTTP request failed: " + std::to_string(GetLastError()));
    }
    
    return result;
#else
    throw std::runtime_error("HTTP downloads only supported on Windows");
#endif
}

std::vector<std::pair<std::string, std::string>> 
SignatureUpdater::ParseMalwareBazaarResponse(const std::string& json) {
    std::vector<std::pair<std::string, std::string>> hashes;
    
    // Simple JSON parsing for MalwareBazaar response format:
    // { "data": [ { "sha256_hash": "...", "signature": "..." }, ... ] }
    // We parse without external JSON library for zero dependencies.
    
    std::string searchKey = "\"sha256_hash\":\"";
    std::string sigKey = "\"signature\":";
    size_t pos = 0;
    
    while (pos < json.size() && hashes.size() < m_maxDownload) {
        // Find SHA256 hash
        pos = json.find(searchKey, pos);
        if (pos == std::string::npos) break;
        
        pos += searchKey.size();
        size_t endPos = json.find('"', pos);
        if (endPos == std::string::npos) break;
        
        std::string hash = json.substr(pos, endPos - pos);
        pos = endPos;
        
        // Validate hash (64 hex chars)
        if (hash.size() != 64) continue;
        bool validHex = true;
        for (char c : hash) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) {
                validHex = false;
                break;
            }
        }
        if (!validHex) continue;
        
        // Find signature/name (optional)
        std::string sigName = "MalwareBazaar-" + hash.substr(0, 8);
        size_t sigPos = json.find(sigKey, pos);
        if (sigPos != std::string::npos && sigPos < pos + 500) {
            size_t nameStart = json.find('"', sigPos + sigKey.size());
            if (nameStart != std::string::npos) {
                nameStart++;
                size_t nameEnd = json.find('"', nameStart);
                if (nameEnd != std::string::npos && nameEnd - nameStart < 100) {
                    std::string name = json.substr(nameStart, nameEnd - nameStart);
                    if (!name.empty() && name != "null") {
                        sigName = name;
                    }
                }
            }
        }
        
        hashes.emplace_back(hash, sigName);
    }
    
    return hashes;
}

size_t SignatureUpdater::MergeSignatures(
    const std::vector<std::pair<std::string, std::string>>& newHashes
) {
    if (newHashes.empty()) return 0;
    
    // Load existing hashes to avoid duplicates
    auto existing = LoadExistingHashes();
    
    auto updateFile = m_signatureDir / "online_updates.db";
    std::ofstream file(updateFile, std::ios::app);
    
    if (!file) {
        // Create directory and try again
        std::filesystem::create_directories(m_signatureDir);
        file.open(updateFile, std::ios::app);
        if (!file) {
            m_logger->Error("Cannot write to signature file: {}", updateFile.string());
            return 0;
        }
    }
    
    size_t added = 0;
    for (const auto& [hash, name] : newHashes) {
        if (existing.count(hash) == 0) {
            // threat_level 4 = Critical (from public malware databases)
            file << "SHA256|MB_" << hash.substr(0, 8) << "|" 
                 << name << "|4|" << hash << "\n";
            ++added;
            existing.insert(hash);
        }
    }
    
    file.flush();
    return added;
}

std::unordered_set<std::string> SignatureUpdater::LoadExistingHashes() {
    std::unordered_set<std::string> hashes;
    
    // Scan all .db files in signature directory
    if (!std::filesystem::exists(m_signatureDir)) return hashes;
    
    for (const auto& entry : std::filesystem::directory_iterator(m_signatureDir)) {
        if (entry.path().extension() != ".db") continue;
        
        std::ifstream file(entry.path());
        std::string line;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;
            
            // Extract hash from TYPE|ID|NAME|LEVEL|HASH format
            size_t lastPipe = line.rfind('|');
            if (lastPipe != std::string::npos && lastPipe + 1 < line.size()) {
                std::string hash = line.substr(lastPipe + 1);
                // Trim whitespace
                while (!hash.empty() && (hash.back() == '\r' || hash.back() == '\n' || hash.back() == ' ')) {
                    hash.pop_back();
                }
                if (hash.size() == 64) {
                    hashes.insert(hash);
                }
            }
        }
    }
    
    return hashes;
}

}  // namespace antivirus
