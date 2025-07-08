# RTCVEF - Red Team CVE Exploit Framework

A comprehensive, modular framework for CVE analysis and exploit generation designed for authorized penetration testing and red team operations.

## 🚨 WARNING

**This tool is for authorized penetration testing only!**
- Ensure you have explicit permission before using this tool
- Only use in controlled environments with proper authorization
- Misuse of this tool may violate laws and regulations

## 📋 Overview

RTCVEF (Red Team CVE Exploit Framework) is a Python-based framework that automates:
- CVE data retrieval from National Vulnerability Database (NVD)
- Exploit search from Exploit-DB
- Vulnerability classification using CWE mapping
- Shellcode generation for Linux/Windows platforms
- Python stager creation for payload delivery

## 🏗️ Architecture

The framework follows a modular design with the following components:

```
RTCVEF/
├── utils/              # Configuration and logging utilities
├── cve_parser/         # CVE data fetching and parsing
├── vuln_classifier/    # Vulnerability classification engine
├── exploit_generator/  # Shellcode and stager generation
├── main.py            # Main CLI interface
└── requirements.txt   # Python dependencies
```

## 🔧 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Internet connection for CVE/exploit lookup

### Setup

1. Clone or download the RTCVEF framework
2. Navigate to the RTCVEF directory
3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. (Optional) Set up environment variables:
```bash
export NVD_API_KEY="your_nvd_api_key_here"
export RTCVEF_OUTPUT_DIR="/path/to/output/directory"
```

5. Test the framework:
```bash
python test_framework.py
```

6. Run CVE analysis:
```bash
python RTCVEF/main.py CVE-2023-1234
```

## 🚀 Usage

### Basic Usage

Analyze a CVE:
```bash
python RTCVEF/main.py CVE-2023-1234
```

### Advanced Usage

Generate exploit payload:
```bash
python RTCVEF/main.py CVE-2023-1234 --generate-exploit --ip 192.168.1.100 --port 4444
```

Target specific platform:
```bash
python RTCVEF/main.py CVE-2023-1234 --os linux --arch x64 --generate-exploit
```

Verbose output:
```bash
python RTCVEF/main.py CVE-2023-1234 --verbose
```

### Command Line Options

```
usage: main.py [-h] [--generate-exploit] [--ip IP] [--port PORT] 
               [--os {linux,windows}] [--arch {x86,x64}] [--output-dir OUTPUT_DIR] 
               [--format {text,json}] [--no-confirmation] [--verbose] [--debug]
               cve_id

Required Arguments:
  cve_id                CVE identifier (e.g., CVE-2023-1234)

Exploit Generation:
  --generate-exploit, -g
                        Generate exploit payload for supported vulnerability types
  --ip IP               Target IP address for reverse shell (default: 127.0.0.1)
  --port PORT, -p PORT  Target port for reverse shell (default: 4444)
  --os {linux,windows}  Target operating system (default: linux)
  --arch {x86,x64}      Target architecture (default: x86)

Output Options:
  --output-dir OUTPUT_DIR, -o OUTPUT_DIR
                        Output directory for generated files
  --format {text,json}  Output format (default: text)

Behavior Options:
  --no-confirmation     Skip user confirmation prompts
  --verbose, -v         Enable verbose logging
  --debug               Enable debug logging
```

## 🎯 Features

### CVE Analysis
- Fetches CVE details from NVD API
- Searches for exploits in Exploit-DB
- Extracts vulnerability metadata (CVSS, CWE, references)
- Provides comprehensive vulnerability assessment

### Vulnerability Classification
- Rule-based classification using keyword patterns
- CWE-to-vulnerability-type mapping
- Confidence scoring for classifications
- Support for multiple vulnerability types:
  - Remote Code Execution (RCE)
  - Buffer Overflow (BOF)
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Authentication Bypass
  - Privilege Escalation
  - And more...

### Exploit Generation
- Linux x86/x64 shellcode generation
- Windows shellcode templates
- Python stager creation
- Reverse shell and bind shell payloads
- Customizable IP/port configuration

### Supported Platforms
- **Linux**: x86, x64 architectures
- **Windows**: x86, x64 architectures (templates)
- **Stagers**: Python-based payload delivery

## 📊 Example Output

```
╔══════════════════════════════════════════════════════════════════════════════╗
║              Red Team CVE Exploit Framework v1.0                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

[*] Fetching CVE details for CVE-2023-1234...
[+] CVE details retrieved successfully
[*] Searching Exploit-DB for CVE-2023-1234...
[+] Found 2 exploit(s) in Exploit-DB
[*] Classifying vulnerability type...
[+] Classification completed
    Primary Type: RCE
    Confidence: 0.85
    Method: CWE_ANALYSIS

================================================================================
CVE ANALYSIS SUMMARY
================================================================================

CVE Information:
  ID: CVE-2023-1234
  Severity: HIGH (7.5)
  Published: 2023-06-15
  CWE(s): CWE-89, CWE-78

Description:
  SQL injection vulnerability in Example Application allows remote
  attackers to execute arbitrary SQL commands...

Vulnerability Classification:
  Primary Type: RCE
  Confidence: 0.85
  Classification Method: CWE_ANALYSIS

Exploit Information:
  Exploit-DB Entries: 2
    - Example RCE Exploit (EDB-12345)
    - SQL Injection to RCE (EDB-12346)

[*] Use --generate-exploit to create exploit payload
[+] Analysis completed successfully for CVE-2023-1234
```

## 🔍 Framework Components

### Utils Module
- **config.py**: Configuration management with API settings and security parameters
- **logger.py**: Comprehensive logging system with audit trails

### CVE Parser Module
- **nvd_api.py**: NVD API integration with rate limiting and error handling
- **cve_scraper.py**: Exploit-DB scraping with BeautifulSoup

### Vulnerability Classifier Module
- **cwe_mapper.py**: CWE-to-vulnerability-type mapping with 50+ definitions
- **classify.py**: Rule-based classification with confidence scoring

### Exploit Generator Module
- **shellcode_gen.py**: Shellcode generation for multiple platforms
- **stager_builder.py**: Python stager creation with evasion techniques

## 🛡️ Security Considerations

### Responsible Use
- Only use on systems you own or have explicit permission to test
- Follow responsible disclosure practices
- Respect rate limits and API terms of service
- Maintain audit logs of all activities

### Framework Security
- API keys stored securely (environment variables)
- Rate limiting to prevent API abuse
- Comprehensive logging for accountability
- Input validation for all user inputs

## 🔧 Configuration

The framework uses `utils/config.py` for configuration management:

```python
# API Configuration
nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
nvd_api_key = os.getenv("NVD_API_KEY", "")

# Output Configuration
output_directory = os.getenv("RTCVEF_OUTPUT_DIR", "./output")

# Security Settings
max_cve_per_session = 10
require_user_confirmation = True
```

## 🚨 Limitations

### Current Limitations
- Windows shellcode generation uses templates (not fully functional)
- Limited to basic reverse/bind shell payloads
- No advanced evasion techniques implemented
- Single-threaded operation

### Supported Vulnerability Types
- **Full Support**: RCE, BOF
- **Analysis Only**: SQLi, XSS, Auth Bypass, Privilege Escalation, etc.

## 📝 Development

### Adding New Vulnerability Types
1. Update `vuln_classifier/cwe_mapper.py` with new CWE mappings
2. Add classification rules in `vuln_classifier/classify.py`
3. Implement exploit generation in `exploit_generator/`

### Adding New Stager Types
1. Create new template in `exploit_generator/stager_builder.py`
2. Add to `templates` dictionary in `StagerBuilder` class
3. Update documentation and help text

## 🤝 Contributing

This framework is designed for educational and authorized testing purposes. 
When contributing:
- Follow responsible disclosure practices
- Ensure all code is well-documented
- Add appropriate security warnings
- Test thoroughly in controlled environments

## 📜 License

This tool is provided for educational and authorized penetration testing purposes only. 
Users are responsible for ensuring compliance with all applicable laws and regulations.

## 🙏 Acknowledgments

- National Vulnerability Database (NVD) for CVE data
- Exploit-DB for exploit information
- Security research community for vulnerability insights

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.** 
