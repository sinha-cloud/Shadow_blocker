# 🛡️ ShadowBlocker

**ShadowBlocker** is a premium, privacy-first local forensic auditor for installed browser extensions. It automatically analyzes extension source files on your device to flag hidden security threats, keyloggers, session harvesters, and malicious obfuscation—**completely offline, without sending any data to the cloud**.

Many browser extensions are bought out or updated secretly with malicious code that reads keystrokes, steals cookies, intercepts active tabs, and exfiltrates credentials. ShadowBlocker audits your browser environments directly, giving you complete visibility into the security posture of your extensions.

---

## ✨ Features

- **🚀 Automated Browser Discovery Engine**: Instantly locates Chrome, Microsoft Edge, and Brave extensions under all user profiles on Windows.
- **🔑 Deep Manifest Audit**: Evaluates permissions and hosts, mapping out risk levels (Safe, Warning, Critical) based on potential security exposure.
- **🔍 JavaScript Static Analyzer**: Analyzes content and background scripts line-by-line using regular expression-based signature detection:
  - **Keylogging capturing**: Catches standard keyboard listeners (`keydown`, `keyup`, `keypress`).
  - **Cookie & Session harvesting**: Flags `chrome.cookies` extraction API or `localStorage` dumping loops.
  - **Network Exfiltration**: Triggers alerts on fetch requests pointing to raw IP addresses or cheap, obscure top-level domains (e.g. `.xyz`, `.top`, `.ru`).
  - **Obfuscation & Packers**: Catches Dean Edwards JS Packers, base64 dynamically decoded `eval(atob(...))` loaders, and random function calls.
- **🖥️ Asynchronous CustomTkinter Dashboard**: Features a high-performance, modern dark/light graphical user interface. Since operations execute inside dedicated worker threads, the dashboard is incredibly responsive and never freezes during deep directory scans.
- **📤 Exportable Reports**: Allows exporting beautiful, responsive forensic audit reports as HTML.

---

## 📁 Repository Structure

```text
e:/code/shadowblocker/
├── main.py                     # Main application entry point
├── requirements.txt            # Python library dependencies
├── README.md                   # Setup and usage documentation
├── shadowblocker/              # Core source package
│   ├── __init__.py
│   ├── models.py               # Standardized data objects (ExtensionInfo, AnalysisFinding, etc.)
│   ├── discovery.py            # Chromium directory profile scan engine
│   ├── scanner.py              # Manifest analyzer, signature matcher & risk scoring
│   └── gui.py                  # Responsive CustomTkinter dashboard implementation
├── test_extensions/            # Mock extensions for secure sandboxed analysis testing
│   ├── safe_extension/         # A standard, safe notepad-taking extension
│   └── suspicious_extension/   # A full-featured malicious simulation (contains keylogger & exfil)
└── tests/                      # Python unit test suite
    ├── __init__.py
    └── test_scanner.py         # Static analyzer & scoring logic tests
```

---

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.10 or higher
- Windows OS (Default browser discovery patterns are optimized for Windows paths)

### 1. Install Dependencies
Open your command terminal inside the project directory and install the required modules:
```bash
pip install -r requirements.txt
```

---

## 🚀 Running ShadowBlocker

To start the desktop application, run the `main.py` entrypoint:
```bash
python main.py
```

### 💡 Initial Mock Testing
On startup, **ShadowBlocker automatically pre-loads and scans the local `test_extensions/` folder** within your workspace to showcase its forensic capabilities:
- Inspect the **Super AdBlocker Pro Max** (simulating a bought-out extension). Click it to see exactly which lines of keylogger code, cookie harvesting API loops, dynamic Base64 evaluation, and raw IP exfiltration fetch endpoints triggered the critical risk alert.
- Compare it with **Sleek Note Taker** which uses standard local storage storage safely.

---

## 🔬 Threat Signatures List

ShadowBlocker matches several patterns to identify advanced threats:

| Signature | Risk Level | Description |
|---|---|---|
| **Keylogging Listener** | `CRITICAL` | Listens to `keydown`/`keyup`/`keypress` on active browser windows. |
| **Cookie Harvest API** | `CRITICAL` | Requests all cookies on any active session via `chrome.cookies.getAll`. |
| **Exfiltration to Raw IP** | `CRITICAL` | Routes HTTP/Socket traffic directly to a raw IP address (bypassing DNS list blocks). |
| **Base64 execution** | `CRITICAL` | Conceals payload text inside base64, decoding and running it via `eval(atob(...))`. |
| **Obfuscated Packers** | `CRITICAL` | Hides script logic using Dean Edwards or other common JS packers. |
| **localStorage Dumper** | `WARNING` | Iterates over local storage keys to dump raw session identifiers. |
| **Obscure Domain Host** | `WARNING` | Interfaces with high-risk top-level domains (e.g. `.xyz`, `.top`, `.tk`, `.ru`). |

---

## 🧪 Running Unit Tests

The core scanning and risk calculations are backed by automated tests. To run them, execute:
```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 📦 Sharing & Standalone Distribution

You can share **ShadowBlocker** with another system using one of the following methods:

### Method 1: Share as a Standalone Executable (`.exe`) - Recommended for End-Users
You can package the application into a single `.exe` file. The recipient can run it immediately on any Windows machine **without needing to install Python, git, or any external libraries**.

1. Install PyInstaller in your virtual environment:
   ```bash
   pip install pyinstaller
   ```
2. Build the standalone executable:
   ```bash
   pyinstaller --noconsole --onefile --name ShadowBlocker main.py
   ```
   *Note: `--noconsole` hides the terminal shell window in the background, and `--onefile` bundles everything into a single file.*
3. Retrieve your compiled file from the newly created `dist/` directory:
   ```text
   dist/ShadowBlocker.exe
   ```
4. **Copy and Share**: Simply send the `ShadowBlocker.exe` file to any other Windows computer!

### Method 2: Share via GitHub (For Developers & Technical Users)
Since the project is already published on GitHub, other developers can run it directly from source:

1. On the target machine, clone the repository:
   ```bash
   git clone https://github.com/sinha-cloud/Shadow_blocker.git
   cd Shadow_blocker
   ```
2. Set up a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python main.py
   ```

