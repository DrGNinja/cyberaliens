# Cyb3rALIENS – Comprehensive Final Simulation Package

Pure-software reference implementation and interactive demonstration of the dual-microcontroller Point-to-Point Encryption architecture described in **US Patent 10,673,617 B1**.

This package is designed so investors, customers, and technical reviewers can experience the complete system flow as if the hardware and software were running in production — without any physical devices.

---

## Two Ways to Demonstrate

### 1. Instant Browser Demo (recommended for meetings)
Open this file in any modern browser (no server, no install):

```
web/full_demo.html
```

**Features:**
- Full patent process pipeline (Boot → Entropy → DNA → Cipher 1 → I2C → Cipher 2 / 10 rounds → IAM → BCE → P2PE)
- Multi-device fleet with click-to-select active pair
- IAM central database table (DNA, MAC, serial, validation, firmware)
- Hash-chained BCE ledger
- Self-test report
- Exportable JSON demo report
- Failure injection (entropy fail, key mismatch, revoke block)
- Guided Demo walkthrough with narrative steps
- Live event log and process trace

### 2. C++ Reference Implementation (production-grade core)
```bash
# Requires OpenSSL development headers and CMake
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/cyb3raliens_sim --web          # → http://localhost:8080
./build/cyb3raliens_sim --demo         # console narrative
./build/cyb3raliens_tests              # 22 unit tests
```

Docker:
```bash
docker compose up --build
```

The C++ engine implements the same architecture with OpenSSL AES-256, persistent IAM + ledger files, process tracing, fleet support, and the full JSON API.

---

## Patent Alignment

| Stage | What the simulation shows |
|-------|---------------------------|
| Dual MC-A / MC-B | Master/Slave boot, entropy collection, DNA creation |
| I2C | Simulated bus start, half-key exchange, ACK |
| Cipher 1 | 256-bit AES-SEA half on each microcontroller |
| Cipher 2 | 10-round mixing → shared 512-bit validation key |
| Entropy | Time + clock-jitter sources with health status |
| IAM Central DB | Registration, MAC/serial, validation, status, last-tx |
| BCE Ledger | Hash-chained immutable events (REGISTER, MSG, REVOKE) |
| P2PE | Bidirectional encrypted channel with integrity proof |

All stages are logged in the live process pipeline so a non-technical observer can follow the exact sequence.

---

## Investor Demo Script (2–3 minutes)

1. Open `web/full_demo.html`
2. Click **Guided Demo** or manually:
   - **Onboard Pair** → watch the pipeline fill with Boot / Entropy / DNA / Cipher 1 / I2C / Cipher 2 / IAM / BCE
   - **Send P2PE** → integrity verified
   - Inspect IAM table and BCE ledger
   - Click **Self-Test** → PASS
   - Click **Export** → download the full report
3. Optional: inject a failure and show how the system surfaces it in the pipeline and log

---

## Project Layout

```
cyb3raliens_sim/
├── web/
│   ├── full_demo.html      ← self-contained browser demo (start here)
│   └── index.html          ← UI for the C++ web server
├── src/ include/           ← C++ reference implementation
├── tests/                  ← unit tests
├── Dockerfile docker-compose.yml
├── LICENSE README.md
└── data/                   ← persistence (when using C++ binary)
```

---

## License & Disclaimer

MIT License for the simulation code.  
This is an independent educational and research simulation of the high-level architecture in US10673617B1. It is not an official product, not a bit-exact proprietary implementation, and does not grant any patent license.

---

**Ready for demonstration.**  
Open `web/full_demo.html` and walk the full patented system in under three minutes.
