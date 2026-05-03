# 🛡️ NetLog: Cyber Log Analyzer & IPS

![Version](https://img.shields.io/badge/version-v2.0-blue.svg)
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)
![C++](https://img.shields.io/badge/language-C%2B%2B98%2F11-orange.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

> **"Veni, Vidi, Vici"**  
> An interactive, command-line Intrusion Detection and Prevention System (IDS/IPS) built in C++.

---

## 📖 Table of Contents
1. Introduction  
2. Core Functionality  
3. Technology Stack  
4. Project Structure  
5. Core Logic & Threat Engine  
6. System Pseudocode  
7. Installation & Usage  
8. Development Team  

---

## 🚀 Introduction

**NetLog** is a lightweight, high-performance command-line application designed to simulate an enterprise-grade log analyzer and firewall management system.  

It processes complex server logs, tokenizes network events, and utilizes a rule-based Threat Engine to automatically score and categorize suspicious activities.  

Beyond passive analysis, NetLog operates as an active **Intrusion Prevention System (IPS)**, allowing administrators to:
- Review IP addresses  
- Apply `BLOCKED` or `SAFE` rules  
- Maintain persistent firewall states  

---

## ✨ Core Functionality

- Advanced Log Parsing using `std::stringstream`
- Rule-Based Threat Scoring (1–10 severity scale)
- Interactive Command-Line Interface (`scan`, `summary`, `ip_list`)
- Real-Time Firewall Management (`block <ip>`, `safe <ip>`)
- Data Persistence using file overwrite (`std::ofstream`)
- Terminal UI with colors, progress bars, and ASCII design

---

## 🛠️ Technology Stack

- **Language:** C++ (Standard Library)  
- **File Handling:** `<fstream>`  
- **Parsing:** `<string>`, `<sstream>`  
- **Formatting:** `<iomanip>`  
- **OS APIs:** `<windows.h>`  

---

## 📁 Project Structure


NetLog/
│
├── src/
│ └── main.cpp
│
├── data/
│ └── logs.txt
│
├── docs/
│ └── README.md
│
├── Makefile.win
└── NetLog.exe


---

## 🧠 Core Logic & Threat Engine

| Attack Type        | Status   | Threat Level | Score |
|-------------------|----------|-------------|-------|
| SQL Injection     | BLOCKED  | CRITICAL    | 10    |
| XSS Attack        | BLOCKED  | CRITICAL    | 10    |
| Port Scan         | DETECTED | HIGH        | 8     |
| Login Failed      | FAILED   | HIGH        | 7     |
| Invalid Auth      | FAILED   | MEDIUM      | 6     |
| Login / Ping      | SUCCESS  | LOW         | 1     |
| Unknown Activity  | ANY      | MEDIUM      | 3     |

---

## 📜 System Pseudocode


START PROGRAM NetLog

LOAD logs
SORT logs by threat score

WHILE system running:
TAKE user input

IF "summary" → show summary
IF "scan" → show report
IF "ip_list" → show IPs

IF "block <ip>" → mark BLOCKED + save
IF "safe <ip>" → mark SAFE + save

IF "exit" → stop program

END


---

## 💻 Installation & Usage

### Prerequisites
- C++ Compiler (GCC / MinGW / MSVC)
- Windows OS

### Compile
```bash
g++ main.cpp -o NetLog.exe
Run
./NetLog.exe

Provide the log file path when prompted (e.g., ../data/logs.txt)

Use help command to view available options.

👥 Development Team

Team Overwriters

sp4Panda — Lead Architect & Software Engineer

Developed as part of the Programming Fundamentals curriculum at COMSATS University.


---

✅ I converted and cleaned your file from: :contentReference[oaicite:0]{index=0}  

If you want, I can:
- add **GitHub badges properly linked**
- make it **more beginner-friendly**
- or turn it into a **portfolio-level README (very impressive for CVs)**
