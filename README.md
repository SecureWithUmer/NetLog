# 🛡️ NetLog: Cyber Log Analyzer & IPS

![Version](https://img.shields.io/badge/version-v2.0-blue.svg)
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)
![C++](https://img.shields.io/badge/language-C%2B%2B98%2F11-orange.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

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


// ========================================================
// PSEUDOCODE: NETLOG (CYBER LOG ANALYZER & FIREWALL IPS)
// ========================================================

// 1. DATA STRUCTURE DEFINITION
STRUCTURE LogEntry:
    ipAddress (Text)
    timestamp (Text)
    action (Text)
    status (Text)
    severityScore (Number)
    threatLevel (Text)
    ipStatus (Text) // BLOCKED, SAFE, or UNVERIFIED
END STRUCTURE

CONSTANTS:
    MAX_LOGS = 100

// ========================================================
// 2. MAIN PROGRAM FLOW
// ========================================================
BEGIN MAIN:
    DECLARE securityLogs AS Array of LogEntry of size MAX_LOGS
    DECLARE totalLogs = 0
    DECLARE activeFilePath = ""
    DECLARE inputLine = ""

    CALL displayBanner()

    // Phase 1: Setup and File Loading
    WHILE TRUE:
        PRINT "Please enter the log file path to begin: "
        READ activeFilePath
        
        REMOVE quote characters from activeFilePath IF present
        
        totalLogs = CALL loadAndScoreLogs(securityLogs, activeFilePath)
        
        IF totalLogs > 0 THEN
            PRINT "File added successfully!"
            CALL sortLogs(securityLogs, totalLogs)
            BREAK loop
        END IF
    END WHILE

    PRINT Available Commands Menu

    // Phase 2: Interactive Command Shell
    WHILE TRUE:
        PRINT "root@netlog:~# "
        READ inputLine
        
        IF inputLine is empty THEN
            CONTINUE to next iteration
            
        IF inputLine == "summary" THEN
            CALL displaySummary(securityLogs, totalLogs)
            
        ELSE IF inputLine == "scan" THEN
            CALL generateReport(securityLogs, totalLogs)
            
        ELSE IF inputLine == "ip_list" THEN
            CALL displayIPList(securityLogs, totalLogs)
            
        ELSE IF inputLine STARTS WITH "block " THEN
            targetIP = EXTRACT IP from inputLine
            CALL updateIPStatus(securityLogs, totalLogs, activeFilePath, targetIP, "BLOCKED")
            
        ELSE IF inputLine STARTS WITH "safe " THEN
            targetIP = EXTRACT IP from inputLine
            CALL updateIPStatus(securityLogs, totalLogs, activeFilePath, targetIP, "SAFE")
            
        ELSE IF inputLine == "clear" THEN
            CLEAR console screen
            CALL displayBanner()
            
        ELSE IF inputLine == "help" THEN
            PRINT Commands Menu
            
        ELSE IF inputLine == "exit" THEN
            PRINT "Shutting down..."
            BREAK loop
            
        ELSE
            PRINT "Invalid command error"
        END IF
    END WHILE
END MAIN

// ========================================================
// 3. CORE FUNCTION DEFINITIONS
// ========================================================

FUNCTION loadAndScoreLogs(logsArray, filepath):
    OPEN file at filepath for READING
    IF file cannot be opened THEN
        PRINT "ERROR"
        RETURN 0
        
    DECLARE count = 0
    WHILE end of file NOT reached AND count < MAX_LOGS:
        READ current line of text
        
        // String Slicing
        EXTRACT ipAddress from line
        EXTRACT timestamp from line
        EXTRACT action from line
        EXTRACT status from line
        
        // Firewall Status Check
        IF ipStatus exists at end of line THEN
            EXTRACT ipStatus
        ELSE
            SET ipStatus = "UNVERIFIED"
            
        // Rule-Based Threat Engine
        IF action == "SQL_INJECTION" OR action == "XSS_ATTACK" THEN
            SET severityScore = 10, threatLevel = "CRITICAL"
        ELSE IF action == "PORT_SCAN" THEN
            SET severityScore = 8, threatLevel = "HIGH"
        ELSE IF action == "LOGIN" AND status == "FAILED" THEN
            SET severityScore = 7, threatLevel = "HIGH"
        ELSE IF action == "INVALID_AUTH" THEN
            SET severityScore = 6, threatLevel = "MEDIUM"
        ELSE IF status == "SUCCESS" OR action == "PING" THEN
            SET severityScore = 1, threatLevel = "LOW"
        ELSE
            SET severityScore = 3, threatLevel = "MEDIUM"
            
        INCREMENT count
    END WHILE
    
    CLOSE file
    RETURN count
END FUNCTION


FUNCTION sortLogs(logsArray, totalLogs):
    // Bubble Sort Algorithm (Descending)
    FOR i = 0 TO totalLogs - 1:
        FOR j = 0 TO totalLogs - i - 1:
            IF logsArray[j].severityScore < logsArray[j + 1].severityScore THEN
                temp = logsArray[j]
                logsArray[j] = logsArray[j + 1]
                logsArray[j + 1] = temp
            END IF
        END FOR
    END FOR
END FUNCTION


FUNCTION displaySummary(logsArray, totalLogs):
    DECLARE Counters: crit=0, high=0, med=0, low=0
    DECLARE Counters: blocked=0, safe=0, unverified=0
    
    FOR i = 0 TO totalLogs - 1:
        INCREMENT matching threatLevel counter
        INCREMENT matching ipStatus counter
    END FOR
    
    PRINT "THREAT SUMMARY"
    PRINT Threat Level Counts
    PRINT Firewall Status Counts
END FUNCTION


FUNCTION generateReport(logsArray, totalLogs):
    PRINT Table Headers
    
    FOR i = 0 TO totalLogs - 1:
        // Full-Row Color Logic
        IF ipStatus == "BLOCKED" THEN
            SET COLOR RED
        ELSE IF ipStatus == "SAFE" THEN
            SET COLOR GREEN
        ELSE
            SET COLOR based on threatLevel
            
        PRINT logsArray[i] variables in formatted columns
        RESET COLOR
    END FOR
END FUNCTION


FUNCTION displayIPList(logsArray, totalLogs):
    DECLARE uniqueIPs Array
    DECLARE uniqueStatus Array
    DECLARE uniqueCount = 0
    
    // Find Unique IPs
    FOR i = 0 TO totalLogs - 1:
        IF logsArray[i].ipAddress IS NOT IN uniqueIPs THEN
            ADD logsArray[i].ipAddress TO uniqueIPs
            ADD logsArray[i].ipStatus TO uniqueStatus
            INCREMENT uniqueCount
        END IF
    END FOR
    
    PRINT "UNIQUE IP LIST"
    FOR i = 0 TO uniqueCount - 1:
        SET COLOR based on uniqueStatus[i]
        PRINT uniqueIPs[i] AND uniqueStatus[i]
        RESET COLOR
    END FOR
END FUNCTION


FUNCTION updateIPStatus(logsArray, totalLogs, filepath, targetIP, newStatus):
    DECLARE found = FALSE
    
    // Update Array in Memory
    FOR i = 0 TO totalLogs - 1:
        IF logsArray[i].ipAddress == targetIP THEN
            logsArray[i].ipStatus = newStatus
            found = TRUE
        END IF
    END FOR
    
    // Trigger Persistence and UI Update
    IF found == TRUE THEN
        CALL saveFile(logsArray, totalLogs, filepath)
        PRINT "SUCCESS"
        CALL displaySummary(logsArray, totalLogs)
        CALL generateReport(logsArray, totalLogs)
    ELSE
        PRINT "ERROR: IP Not Found"
    END IF
END FUNCTION


FUNCTION saveFile(logsArray, totalLogs, filepath):
    OPEN file at filepath for WRITING (Overwrite Mode)
    
    FOR i = 0 TO totalLogs - 1:
        WRITE logsArray[i] variables in original string format to file
    END FOR
    
    CLOSE file
END FUNCTION


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

Team Overwriters:
Umer Farooq
Amna Zahid
Hania Asif

Developed as part of the Programming Fundamentals Lab Project at The University of Lahore.

