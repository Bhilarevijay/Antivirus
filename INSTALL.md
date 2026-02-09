# Antivirus Installation & Build Guide

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| **Windows 10/11 x64** | ✅ Full Support | Primary target, all features |
| **Linux** | ⚠️ Partial | Core algorithms work, Windows APIs stubbed |
| **macOS** | ⚠️ Partial | Similar to Linux |

### Linux Compatibility
The codebase is **partially portable** to Linux:
- ✅ **Works**: Hash engine, Bloom filter, Aho-Corasick, thread pool, logging
- ❌ **Windows-only**: ACL permissions, native file enumeration, GPU detection

To run on Linux, you'd need to add `#ifdef __linux__` implementations for file scanning and quarantine ACLs.

---

## Windows Installation (Full Guide)

### Step 1: Install Visual Studio 2022

1. Download **Visual Studio 2022 Community** (free):
   https://visualstudio.microsoft.com/downloads/

2. Run installer and select:
   - ✅ **Desktop development with C++**
   - ✅ **C++ CMake tools for Windows**
   - ✅ **Windows 10/11 SDK (10.0.19041.0 or later)**

3. Click **Install** (requires ~8GB disk space)

![VS Installer](https://learn.microsoft.com/en-us/visualstudio/install/media/vs-2022/vs-installer-workloads.png)

---

### Step 2: Install Git (if not installed)

1. Download Git for Windows:
   https://git-scm.com/download/win

2. Run installer with default options

3. Verify in PowerShell:
   ```powershell
   git --version
   # Should show: git version 2.x.x
   ```

---

### Step 3: Clone the Repository

Open **PowerShell** or **Command Prompt**:

```powershell
# Navigate to where you want the project
cd C:\Projects

# Clone
git clone https://github.com/Bhilarevijay/Antivirus.git

# Enter directory
cd Antivirus
```

---

### Step 4: Build with CMake

#### Option A: Command Line (Recommended)

```powershell
# Create build directory
mkdir build
cd build

# Generate Visual Studio solution
cmake .. -G "Visual Studio 17 2022" -A x64

# Build Release version
cmake --build . --config Release

# Build Debug version (optional, for development)
cmake --build . --config Debug
```

#### Option B: Visual Studio GUI

1. Open Visual Studio 2022
2. Click **Open a local folder**
3. Select the `Antivirus` folder
4. Wait for CMake configuration (see Output window)
5. Select **Release** from dropdown (top toolbar)
6. Click **Build → Build All** (or press `Ctrl+Shift+B`)

---

### Step 5: Verify Build

After successful build, you'll find:

```
Antivirus/
└── build/
    └── Release/
        └── antivirus.exe    ← Your executable!
```

Test it:
```powershell
.\build\Release\antivirus.exe --help
```

Expected output:
```
High-Performance Antivirus Scanner
===================================

Usage: antivirus.exe [command] [options]

Commands:
  scan <path>      Scan specified path
  quick            Quick scan (common malware locations)
  full             Full system scan
  quarantine       Manage quarantined files
  status           Show engine status
  help             Show this help
```

---

### Step 6: Run Scans

```powershell
# Quick scan (common locations)
.\build\Release\antivirus.exe quick

# Scan specific folder
.\build\Release\antivirus.exe scan C:\Users\%USERNAME%\Downloads

# Full system scan (run as Administrator!)
# Right-click PowerShell → "Run as Administrator"
.\build\Release\antivirus.exe full

# View quarantine
.\build\Release\antivirus.exe quarantine list
```

---

## Optional: Enable CUDA (GPU Acceleration)

### Prerequisites
- NVIDIA GPU (GTX 10xx or newer)
- CUDA Toolkit 11.0+: https://developer.nvidia.com/cuda-downloads

### Build with CUDA
```powershell
cmake .. -G "Visual Studio 17 2022" -A x64 -DENABLE_CUDA=ON
cmake --build . --config Release
```

---

## Project Structure After Build

```
Antivirus/
├── build/
│   ├── Release/
│   │   └── antivirus.exe
│   └── Debug/
│       └── antivirus.exe
├── include/           # Header files
├── src/               # Source files
├── signatures/
│   └── malware_signatures.db
├── CMakeLists.txt
└── README.md
```

---

## Troubleshooting

### "cmake not found"
- Open **Developer Command Prompt for VS 2022** instead of regular PowerShell
- Or add CMake to PATH: `C:\Program Files\CMake\bin`

### "MSVC compiler not found"
- Ensure "Desktop development with C++" workload is installed
- Use Developer Command Prompt

### Build errors about C++20
- Ensure Visual Studio 2022 (not 2019) is installed
- Check CMakeLists.txt has: `set(CMAKE_CXX_STANDARD 20)`

### Access denied during scan
- Run as Administrator for system folders
- Some files are locked by Windows (normal)

---

## Linux Build (Experimental)

```bash
# Install dependencies
sudo apt update
sudo apt install build-essential cmake

# Clone
git clone https://github.com/Bhilarevijay/Antivirus.git
cd Antivirus

# Build
mkdir build && cd build
cmake ..
make -j$(nproc)

# Run (limited functionality)
./antivirus scan /home/user/Downloads
```

> **Note**: Windows-specific features (ACL, native APIs) will be stubbed on Linux.
