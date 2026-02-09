/**
 * @file SignatureDatabase.cpp
 * @brief Signature database implementation
 */

#include "antivirus/detection/SignatureDatabase.hpp"
#include <fstream>
#include <sstream>

namespace antivirus {

SignatureDatabase::SignatureDatabase(
    std::shared_ptr<ILogger> logger,
    size_t expectedSignatures
)
    : m_logger(std::move(logger))
    , m_md5Bloom(std::make_unique<BloomFilter>(expectedSignatures, 0.01))
    , m_sha1Bloom(std::make_unique<BloomFilter>(expectedSignatures, 0.01))
    , m_sha256Bloom(std::make_unique<BloomFilter>(expectedSignatures, 0.01))
    , m_patternMatcher(std::make_unique<PatternMatcher>())
{
}

SignatureDatabase::~SignatureDatabase() = default;

bool SignatureDatabase::Load(const std::filesystem::path& path) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    std::ifstream file(path);
    if (!file) {
        m_logger->Warn("Signature database not found: {}", path.string());
        return false;
    }
    
    Clear();
    
    // Simple line-based format:
    // TYPE|ID|NAME|LEVEL|HASH_OR_PATTERN
    std::string line;
    size_t count = 0;
    
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        std::istringstream iss(line);
        std::string type, id, name, levelStr, data;
        
        std::getline(iss, type, '|');
        std::getline(iss, id, '|');
        std::getline(iss, name, '|');
        std::getline(iss, levelStr, '|');
        std::getline(iss, data);
        
        SignatureEntry entry;
        entry.id = id;
        entry.name = name;
        entry.level = static_cast<ThreatLevel>(std::stoi(levelStr));
        
        if (type == "MD5") {
            entry.hashType = HashType::MD5;
            entry.hash = HashEngine::HexToHash(data);
            m_md5Signatures[data] = entry;
            m_md5Bloom->Insert(entry.hash);
        }
        else if (type == "SHA1") {
            entry.hashType = HashType::SHA1;
            entry.hash = HashEngine::HexToHash(data);
            m_sha1Signatures[data] = entry;
            m_sha1Bloom->Insert(entry.hash);
        }
        else if (type == "SHA256") {
            entry.hashType = HashType::SHA256;
            entry.hash = HashEngine::HexToHash(data);
            m_sha256Signatures[data] = entry;
            m_sha256Bloom->Insert(entry.hash);
        }
        else if (type == "PATTERN") {
            entry.hexPattern = HashEngine::HexToHash(data);
            m_patternSignatures[id] = entry;
            m_patternMatcher->AddPattern(data, id);
        }
        
        ++count;
    }
    
    // Build pattern matcher
    m_patternMatcher->Build();
    
    m_logger->Info("Loaded {} signatures from {}", count, path.string());
    return true;
}

bool SignatureDatabase::Save(const std::filesystem::path& path) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    
    std::ofstream file(path);
    if (!file) {
        return false;
    }
    
    file << "# Antivirus Signature Database\n";
    file << "# Format: TYPE|ID|NAME|LEVEL|DATA\n\n";
    
    for (const auto& [hash, entry] : m_md5Signatures) {
        file << "MD5|" << entry.id << "|" << entry.name << "|"
             << static_cast<int>(entry.level) << "|" << hash << "\n";
    }
    
    for (const auto& [hash, entry] : m_sha1Signatures) {
        file << "SHA1|" << entry.id << "|" << entry.name << "|"
             << static_cast<int>(entry.level) << "|" << hash << "\n";
    }
    
    for (const auto& [hash, entry] : m_sha256Signatures) {
        file << "SHA256|" << entry.id << "|" << entry.name << "|"
             << static_cast<int>(entry.level) << "|" << hash << "\n";
    }
    
    for (const auto& [id, entry] : m_patternSignatures) {
        file << "PATTERN|" << entry.id << "|" << entry.name << "|"
             << static_cast<int>(entry.level) << "|"
             << HashEngine::HashToHex(entry.hexPattern) << "\n";
    }
    
    return true;
}

void SignatureDatabase::AddHashSignature(const SignatureEntry& entry) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    std::string hashHex = HashEngine::HashToHex(entry.hash);
    
    switch (entry.hashType) {
        case HashType::MD5:
            m_md5Signatures[hashHex] = entry;
            m_md5Bloom->Insert(entry.hash);
            break;
        case HashType::SHA1:
            m_sha1Signatures[hashHex] = entry;
            m_sha1Bloom->Insert(entry.hash);
            break;
        case HashType::SHA256:
            m_sha256Signatures[hashHex] = entry;
            m_sha256Bloom->Insert(entry.hash);
            break;
    }
}

void SignatureDatabase::AddPatternSignature(const SignatureEntry& entry) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    m_patternSignatures[entry.id] = entry;
    m_patternMatcher->AddPattern(entry.hexPattern, entry.id);
}

std::optional<SignatureEntry> SignatureDatabase::LookupByHash(
    std::span<const uint8_t> hash,
    HashType type
) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    
    std::string hashHex = HashEngine::HashToHex(hash);
    
    switch (type) {
        case HashType::MD5: {
            auto it = m_md5Signatures.find(hashHex);
            if (it != m_md5Signatures.end()) {
                return it->second;
            }
            break;
        }
        case HashType::SHA1: {
            auto it = m_sha1Signatures.find(hashHex);
            if (it != m_sha1Signatures.end()) {
                return it->second;
            }
            break;
        }
        case HashType::SHA256: {
            auto it = m_sha256Signatures.find(hashHex);
            if (it != m_sha256Signatures.end()) {
                return it->second;
            }
            break;
        }
    }
    
    return std::nullopt;
}

bool SignatureDatabase::MayMatchHash(
    std::span<const uint8_t> hash,
    HashType type
) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    
    std::array<uint8_t, 32> hashArray{};
    std::copy_n(hash.begin(), std::min(hash.size(), hashArray.size()), hashArray.begin());
    
    switch (type) {
        case HashType::MD5:
            return m_md5Bloom->MayContainHash(hashArray);
        case HashType::SHA1:
            return m_sha1Bloom->MayContainHash(hashArray);
        case HashType::SHA256:
            return m_sha256Bloom->MayContainHash(hashArray);
    }
    
    return false;
}

std::vector<std::pair<SignatureEntry, size_t>> SignatureDatabase::ScanPatterns(
    std::span<const uint8_t> data
) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    
    std::vector<std::pair<SignatureEntry, size_t>> results;
    
    auto matches = m_patternMatcher->Scan(data);
    
    for (const auto& [sigId, offset] : matches) {
        auto it = m_patternSignatures.find(sigId);
        if (it != m_patternSignatures.end()) {
            results.emplace_back(it->second, offset);
        }
    }
    
    return results;
}

size_t SignatureDatabase::GetSignatureCount() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return GetHashSignatureCount() + GetPatternSignatureCount();
}

size_t SignatureDatabase::GetHashSignatureCount() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_md5Signatures.size() + m_sha1Signatures.size() + m_sha256Signatures.size();
}

size_t SignatureDatabase::GetPatternSignatureCount() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_patternSignatures.size();
}

void SignatureDatabase::Clear() {
    m_md5Signatures.clear();
    m_sha1Signatures.clear();
    m_sha256Signatures.clear();
    m_patternSignatures.clear();
    
    m_md5Bloom->Clear();
    m_sha1Bloom->Clear();
    m_sha256Bloom->Clear();
    
    m_patternMatcher->Clear();
}

void SignatureDatabase::BuildIndexes() {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    m_patternMatcher->Build();
}

}  // namespace antivirus
