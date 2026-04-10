# ⚡ Hunter Flash: High-Speed Behavioral Threat Hunter

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![C](https://img.shields.io/badge/C-Native-blue?style=flat&logo=c)
![OpenMP](https://img.shields.io/badge/OpenMP-Parallel-red?style=flat)
![Status](https://img.shields.io/badge/Status-Production_Ready-success?style=flat)

**Hunter Flash** is an offensive and defensive security pipeline designed to extract, classify, and detect anomalies in massive log files at extreme speeds. 

It combines the best of both worlds: the **raw performance of C** (utilizing direct memory mapping and parallel computing) and the **flexibility of Python** for applying complex cybersecurity heuristics.

## 🚀 The Problem vs. The Solution
Traditional tools built on interpreted languages often choke when processing gigabytes of logs during Incident Response (IR). **Hunter Flash** solves this bottleneck by delegating blocking I/O and sorting operations to a native C DLL, allowing Python to focus exclusively on the detection math.

**Proven Performance:** Capable of parsing, sorting, and fully analyzing **1,000,000 log events in ~130 milliseconds** (end-to-end pipeline execution).

## 🧠 Hybrid Architecture

1. **Native Core (C + OpenMP):** - Utilizes **Memory-Mapped Files (`mmap`)** via the Windows API for *zero-copy* reading.
   - Ultra-fast string parsing mapping IPv4 addresses to `uint32_t` via bitwise operations.
   - Advanced sorting algorithm (**Parallel Introsort** via `#pragma omp task`) with an $O(N \log N)$ worst-case guarantee via HeapSort fallback.
2. **Bridge (CTypes):** Memory-safe interface ensuring zero leaks (manual garbage collection handled via `try...finally` blocks in Python).
3. **Behavioral Engine (Python):** Calculates time-based standard deviations (deltas) and requests-per-second (RPS) rates to identify non-human traffic patterns. Terminal UI rendered via the `Rich` library.

## 🛡️ Detected Attack Vectors
The heuristic engine does not rely on static "signatures." Instead, it analyzes traffic behavior:

* 💥 **L7 API Flood (DDoS):** Massive instant request volume.
* 🌊 **Pulsing Attack:** Rate Limit evasion via intermittent bursts and pauses.
* 🐢 **Low-and-Slow (Slowloris):** Slow exhaustion of server sockets via rhythmic, delayed connections.
* 🤖 **C2 Beaconing:** Malware communication with mathematically periodic intervals.
* 🕵️ **Automated Fuzzing & Scanning:** High-speed directory mapping with consistent temporal deviation.
* 🔑 **Brute Force:** Repetitive authentication attempts on the same endpoint.
* 🕷️ **Data Scraping:** Methodical and continuous data extraction.

## 🧪 Test Engineering (Synthetic Data)
This repository includes a chaos generator (`gerador.py`). Rather than mocking simple random data, it deterministically injects the 7 attack patterns listed above into millions of lines of "clean background noise." This allows for rigorous mathematical validation of the hunter's heuristic rules.

## 🛠️ How to Run

### 1. Compile the Core DLL (Requires GCC with OpenMP)

```bash
pip install -r requirements.txt
````
```bash
gcc -O3 -march=native -fopenmp -shared -static -o core.dll main.c
