# 🛡️ LogShieldAI

An autonomous local **Intrusion Prevention System (IPS)** that leverages AI-powered threat detection to protect systems against brute-force attacks and suspicious authentication patterns.

## Overview

LogShieldAI monitors system authentication logs in real-time, analyzes patterns using a local LLM (via Ollama), and automatically blocks malicious IP addresses. It combines custom regex parsing, intelligent threat analysis, and live dashboard visualization into a single autonomous security agent.

## Key Features

- **Real-Time Log Monitoring**: Continuously tails system authentication logs (e.g., `/var/log/auth.log`) and streams events live
- **Custom Regex Parser**: Extracts and parses SSH authentication events (success/failure patterns) with precision
- **AI-Powered Threat Analysis**: Routes suspicious IP activity to a local LLM to detect brute-force patterns and anomalies
- **Automatic IP Blocking**: Builds incident context windows and executes automated firewall blocks on flagged IPs
- **Live Rich UI Dashboard**: Displays real-time security events in an interactive terminal dashboard with color-coded status indicators
- **Local-First Architecture**: Runs entirely on-device using Ollama—no cloud dependencies, no external API calls

## How It Works

### 1. **Log Stream Processing**
The system tails the target log file and continuously streams authentication events, staying open to capture new entries in real-time.

### 2. **Event Parsing**
Custom regex patterns extract key authentication details:
- Failed password attempts (with IP, user, timestamp)
- Successful authentications (with auth method, user, IP, timestamp)

### 3. **Threat Detection**
When an IP reaches the threat threshold (3+ failed login attempts), the system:
- Builds a context window of all events from that IP
- Submits the pattern to the local LLM (qwen2.5-coder:3b) for analysis
- Receives structured AI verdict with risk score and recommended action

### 4. **Automated Response**
Based on the AI verdict:
- **If "block"**: IP is added to the ban registry (`banned_ips.txt`)
- **If "allow"**: Event is marked as safe and monitoring continues

### 5. **Dashboard Visualization**
A live Rich UI table displays:
- Event timestamps
- Source IPs
- Event type (success/failure)
- AI assessment results
- Action taken (banned, allowed, or monitoring)

## Installation

### Prerequisites
- Python 3.8+
- [Ollama](https://ollama.ai) installed and running locally
- Access to system authentication logs

### Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/idrisrafaqat18/LogShieldAI.git
   cd LogShieldAI
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Ensure Ollama is running**:
   ```bash
   ollama pull qwen2.5-coder:3b
   ollama serve
   ```

## Usage

Run the IPS agent:

```bash
python logshield_ai.py
```

The system will:
1. Initialize monitoring on the target log file
2. Display a live dashboard with incoming authentication events
3. Analyze suspicious patterns in real-time
4. Block malicious IPs automatically
5. Stream all actions to the console UI

**Press `Ctrl+C` to stop monitoring.**

## Configuration

Edit the following variables in `logshield_ai.py` to customize behavior:

```python
MODEL_NAME = "qwen2.5-coder:3b"     # Ollama model to use
TARGET_LOG = "test_auth.log"         # Log file to monitor
BANNED_IP_FILE = "banned_ips.txt"   # Ban registry location
```

## Architecture

```
┌─────────────────────────────────────┐
│  System Auth Logs (tail -f)         │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│  Continuous Log Stream Engine       │
│  (follow_log_file)                  │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│  Regex Parser                       │
│  (parse_log_line)                   │
│  - Extract IP, User, Status, Time   │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│  Threat Analysis                    │
│  - Track IP history                 │
│  - Detect patterns (3+ failures)    │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│  Local LLM via Ollama               │
│  (query_ai_analyst)                 │
│  - Analyze pattern context          │
│  - Return verdict + confidence      │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│  Firewall Action                    │
│  (execute_firewall_block)           │
│  - Block / Allow IP                 │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│  Live Dashboard (Rich UI)           │
│  - Display results in real-time     │
└─────────────────────────────────────┘
```

## Dependencies

- **ollama** (≥0.2.0): Local LLM integration
- **pydantic** (≥2.0.0): Structured output validation
- **rich** (≥13.0.0): Beautiful terminal UI

## Output

### Live Dashboard Display

```
Live Intrusion Pipeline Stream
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ Timestamp    ┃ Source IP     ┃ Event Type    ┃ AI Assessment ┃ Action Taken  ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ Jun 17 10:15 │ 192.168.1.50  │ FAILURE (root)│ Risk: True    │ 💥 BANNED     │
│ Jun 17 10:16 │ 10.0.0.15     │ SUCCESS (user)│ Clean Event   │ ✓ Allowed     │
│ Jun 17 10:17 │ 172.16.0.88   │ FAILURE (root)│ Monitoring... │ Monitoring    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Ban Registry (`banned_ips.txt`)

```
# LogShield AI - Active Ban Registry
IP: 192.168.1.50 | Reason: Multiple failed SSH authentication attempts detected from this IP over a short timeframe. Pattern consistent with automated brute-force attack vector.
IP: 10.0.0.99 | Reason: 5+ rapid failed login attempts in 2 minutes. Confidence: 0.95
```

## Security Considerations

- **Local-Only**: All processing happens on the local machine—no data leaves the system
- **LLM-Agnostic**: Can be adapted to use any Ollama-compatible model
- **Configurable Thresholds**: Adjust sensitivity by modifying failure count threshold
- **Extensible**: Can be expanded to monitor other log patterns (SSH, FTP, HTTP, etc.)

## Future Enhancements

- [ ] Multi-log file monitoring (SSH, FTP, HTTP, etc.)
- [ ] Whitelist management for trusted IPs
- [ ] Persistent ban history and analytics
- [ ] Slack/Email alerting integration
- [ ] Prometheus metrics export
- [ ] Support for multiple LLM models
- [ ] Advanced pattern recognition (DGA detection, credential stuffing, etc.)

## License

This project is open source and available under the MIT License.

## Contributing

Contributions are welcome! Feel free to submit issues, feature requests, or pull requests.

## Author

Created by [idrisrafaqat18](https://github.com/idrisrafaqat18)

---

**Stay secure. 🛡️**
