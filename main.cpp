/*
===========================================================================
    Project: NetLog (Cyber Log Analyzer & IPS)
    Team: Overwriters
    Course: Programming Fundamentals (2nd Semester)
    Description: Direct command-line interface with full-row color coding, 
                 dynamic Firewall Status summaries, and custom ASCII branding.
===========================================================================
*/

#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <sstream>

using namespace std;

// ANSI Color Codes
const string RESET = "\033[0m";
const string GREEN = "\033[32m";
const string RED = "\033[31m";
const string YELLOW = "\033[33m";
const string CYAN = "\033[36m";

const int MAX_LOGS = 100;

struct LogEntry {
    string ipAddress;
    string timestamp;
    string action;
    string status;
    int severityScore;
    string threatLevel;
    string ipStatus; 
};

// --- Function Prototypes ---
void displayBanner();
int loadAndScoreLogs(LogEntry logs[], string filepath);
void sortLogs(LogEntry logs[], int totalLogs);
void displaySummary(LogEntry logs[], int totalLogs);
void generateReport(LogEntry logs[], int totalLogs);
void displayIPList(LogEntry logs[], int totalLogs);
void updateIPStatus(LogEntry logs[], int totalLogs, string filepath, string targetIP, string newStatus);
void saveFile(LogEntry logs[], int totalLogs, string filepath);

// --- Main Program ---
int main() {
    LogEntry securityLogs[MAX_LOGS];
    int totalLogs = 0;
    string activeFilePath;
    string inputLine;

    // Show the custom Team Overwriters Banner
    displayBanner();

    while (true) {
        cout << YELLOW << "[*] Please enter the log file path to begin: " << RESET;
        getline(cin, activeFilePath);

        if (activeFilePath.find('"') != string::npos) {
            string cleaned = "";
            for (int i = 0; i < activeFilePath.length(); i++) {
                if (activeFilePath[i] != '"') cleaned += activeFilePath[i];
            }
            activeFilePath = cleaned;
        }

        totalLogs = loadAndScoreLogs(securityLogs, activeFilePath);
        
        if (totalLogs > 0) {
            cout << GREEN << "\n[+] File added successfully! Loaded " << totalLogs << " entries.\n" << RESET;
            sortLogs(securityLogs, totalLogs);
            break; 
        }
    }

    cout << CYAN << "\nAvailable Commands:\n" << RESET;
    cout << "  " << GREEN << "summary" << RESET << "         : View threat count summary\n";
    cout << "  " << GREEN << "scan" << RESET << "            : View the full detailed log report\n";
    cout << "  " << GREEN << "ip_list" << RESET << "         : View all unique IPs and their firewall status\n";
    cout << "  " << RED   << "block <ip>" << RESET << "      : Block an IP address (e.g., block 192.168.1.1)\n";
    cout << "  " << GREEN << "safe <ip>" << RESET << "       : Mark an IP as safe (e.g., safe 10.0.0.5)\n";
    cout << "  " << GREEN << "clear" << RESET << "           : Clear the terminal screen\n";
    cout << "  " << GREEN << "help" << RESET << "            : Show these commands again\n";
    cout << "  " << GREEN << "exit" << RESET << "            : Quit application\n\n";

    while (true) {
        cout << GREEN << "root@netlog:~# " << RESET;
        getline(cin, inputLine);

        if (inputLine.empty()) continue; 

        if (inputLine == "summary") {
            displaySummary(securityLogs, totalLogs);
        } 
        else if (inputLine == "scan") {
            generateReport(securityLogs, totalLogs);
        } 
        else if (inputLine == "ip_list") {
            displayIPList(securityLogs, totalLogs);
        } 
        else if (inputLine.find("block ") == 0) {
            string targetIP = inputLine.substr(6); 
            updateIPStatus(securityLogs, totalLogs, activeFilePath, targetIP, "BLOCKED");
        } 
        else if (inputLine.find("safe ") == 0) {
            string targetIP = inputLine.substr(5); 
            updateIPStatus(securityLogs, totalLogs, activeFilePath, targetIP, "SAFE");
        } 
        else if (inputLine == "clear") {
            cout << "\033[2J\033[1;1H"; 
            displayBanner();            
        }
        else if (inputLine == "help") {
            cout << CYAN << "\nCommands: summary, scan, ip_list, block <ip>, safe <ip>, clear, exit\n\n" << RESET;
        }
        else if (inputLine == "exit") {
            cout << CYAN << "\n[!] Shutting down NetLog. System Secured.\n" << RESET;
            break; 
        } 
        else {
            cout << RED << "[-] Invalid command. Type 'help' for options.\n" << RESET;
        }
    }
    return 0;
}

// --- Function Definitions ---

void displayBanner() {
    cout << GREEN;
    cout << "    _   __     __  __               \n";
    cout << "   / | / /__  / /_/ /   ____  ____ _\n";
    cout << "  /  |/ / _ \\/ __/ /   / __ \\/ __ `/\n";
    cout << " / /|  /  __/ /_/ /___/ /_/ / /_/ / \n";
    cout << "/_/ |_/\\___/\\__/_____/\\____/\\__, /  \n";
    cout << "                           /____/   \n";
    cout << RESET;
    cout << CYAN << "               NetLog - Cyber Intrusion Detection\n";
    cout << "                   Developed by Team Overwriters\n";
    cout << YELLOW << "                      \"Veni, Vidi, Vici\"\n";
    cout << CYAN << "==============================================================\n\n" << RESET;
}

int loadAndScoreLogs(LogEntry logs[], string filepath) {
    ifstream file(filepath.c_str());
    if (!file.is_open()) {
        cout << RED << "[-] ERROR: Could not open file. Make sure the path is correct.\n" << RESET;
        return 0;
    }

    int count = 0; string line;
    while (count < MAX_LOGS && getline(file, line)) {
        int bStart = line.find('['); int bEnd = line.find(']');
        if (bStart != string::npos && bEnd != string::npos) {
            logs[count].ipAddress = line.substr(0, bStart - 1); 
            logs[count].timestamp = line.substr(bStart + 1, bEnd - bStart - 1);
            
            string remainder = line.substr(bEnd + 2); 
            stringstream ss(remainder);
            ss >> logs[count].action >> logs[count].status;
            
            if (!(ss >> logs[count].ipStatus)) {
                logs[count].ipStatus = "UNVERIFIED"; 
            }
            
            if (logs[count].action == "SQL_INJECTION" || logs[count].action == "XSS_ATTACK") {
                logs[count].severityScore = 10; logs[count].threatLevel = "CRITICAL";
            } else if (logs[count].action == "PORT_SCAN") {
                logs[count].severityScore = 8; logs[count].threatLevel = "HIGH";
            } else if (logs[count].action == "LOGIN" && logs[count].status == "FAILED") {
                logs[count].severityScore = 7; logs[count].threatLevel = "HIGH";
            } else if (logs[count].action == "INVALID_AUTH") {
                logs[count].severityScore = 6; logs[count].threatLevel = "MEDIUM";
            } else if (logs[count].status == "SUCCESS" || logs[count].action == "PING") {
                logs[count].severityScore = 1; logs[count].threatLevel = "LOW";
            } else {
                logs[count].severityScore = 3; logs[count].threatLevel = "MEDIUM";
            }
            count++;
        }
    }
    file.close();
    return count;
}

void sortLogs(LogEntry logs[], int totalLogs) {
    for (int i = 0; i < totalLogs - 1; i++) {
        for (int j = 0; j < totalLogs - i - 1; j++) {
            if (logs[j].severityScore < logs[j + 1].severityScore) {
                LogEntry temp = logs[j]; logs[j] = logs[j + 1]; logs[j + 1] = temp;
            }
        }
    }
}

void displaySummary(LogEntry logs[], int totalLogs) {
    int crit = 0, high = 0, med = 0, low = 0;
    int blocked = 0, safe = 0, unverified = 0;

    for(int i = 0; i < totalLogs; i++) {
        if(logs[i].threatLevel == "CRITICAL") crit++;
        else if(logs[i].threatLevel == "HIGH") high++;
        else if(logs[i].threatLevel == "MEDIUM") med++;
        else if(logs[i].threatLevel == "LOW") low++;

        if(logs[i].ipStatus == "BLOCKED") blocked++;
        else if(logs[i].ipStatus == "SAFE") safe++;
        else unverified++;
    }

    cout << CYAN << "\n================ THREAT SUMMARY ================\n" << RESET;
    cout << "Total Events Analyzed : " << totalLogs << "\n\n";
    
    cout << YELLOW << "[ SYSTEM DETECTION ]\n" << RESET;
    cout << RED << "CRITICAL Threats      : " << crit << RESET << "\n";
    cout << YELLOW << "HIGH Threats          : " << high << RESET << "\n";
    cout << "MEDIUM Threats        : " << med << "\n";
    cout << GREEN << "LOW Threats           : " << low << RESET << "\n\n";

    cout << YELLOW << "[ FIREWALL STATUS ]\n" << RESET;
    cout << RED << "BLOCKED Events        : " << blocked << RESET << "\n";
    cout << GREEN << "SAFE Events           : " << safe << RESET << "\n";
    cout << "UNVERIFIED Events     : " << unverified << "\n";
    cout << CYAN << "================================================\n\n" << RESET;
}

void generateReport(LogEntry logs[], int totalLogs) {
    cout << "\n" << CYAN << "========================================= FULL THREAT REPORT ========================================\n" << RESET;
    cout << left << setw(16) << "IP ADDRESS" << setw(22) << "TIMESTAMP" << setw(16) << "ACTION" 
         << setw(10) << "STATUS" << setw(8)  << "SCORE" << setw(12) << "LEVEL" << "FIREWALL\n"; 
    cout << "-----------------------------------------------------------------------------------------------------\n";

    for (int i = 0; i < totalLogs; i++) {
        
        if (logs[i].ipStatus == "BLOCKED") cout << RED;
        else if (logs[i].ipStatus == "SAFE") cout << GREEN;
        else {
            if (logs[i].threatLevel == "CRITICAL") cout << RED;
            else if (logs[i].threatLevel == "HIGH") cout << YELLOW;
            else cout << GREEN; 
        }

        cout << left << setw(16) << logs[i].ipAddress << setw(22) << logs[i].timestamp << setw(16) << logs[i].action 
             << setw(10) << logs[i].status << setw(8)  << logs[i].severityScore << setw(12) << logs[i].threatLevel;
             
        if (logs[i].ipStatus == "BLOCKED") cout << "[BLOCKED]\n";
        else if (logs[i].ipStatus == "SAFE") cout << "[SAFE]\n";
        else cout << "[UNVERIFIED]\n";
        
        cout << RESET;
    }
    cout << CYAN << "=====================================================================================================\n\n" << RESET;
}

void displayIPList(LogEntry logs[], int totalLogs) {
    string uniqueIPs[MAX_LOGS];
    string uniqueStatus[MAX_LOGS];
    int uniqueCount = 0;

    for (int i = 0; i < totalLogs; i++) {
        bool found = false;
        for (int j = 0; j < uniqueCount; j++) {
            if (uniqueIPs[j] == logs[i].ipAddress) {
                found = true; break;
            }
        }
        if (!found) {
            uniqueIPs[uniqueCount] = logs[i].ipAddress;
            uniqueStatus[uniqueCount] = logs[i].ipStatus;
            uniqueCount++;
        }
    }

    cout << "\n" << CYAN << "------- SUSPICIOUS & KNOWN IP LIST -------\n" << RESET;
    for (int i = 0; i < uniqueCount; i++) {
        
        if (uniqueStatus[i] == "BLOCKED") cout << RED;
        else if (uniqueStatus[i] == "SAFE") cout << GREEN;
        else cout << YELLOW;

        cout << left << setw(18) << uniqueIPs[i];
        
        if (uniqueStatus[i] == "BLOCKED") cout << "[BLOCKED]\n";
        else if (uniqueStatus[i] == "SAFE") cout << "[SAFE]\n";
        else cout << "[UNVERIFIED]\n";
        
        cout << RESET;
    }
    cout << CYAN << "------------------------------------------\n\n" << RESET;
}

void updateIPStatus(LogEntry logs[], int totalLogs, string filepath, string targetIP, string newStatus) {
    bool found = false;
    for (int i = 0; i < totalLogs; i++) {
        if (logs[i].ipAddress == targetIP) {
            logs[i].ipStatus = newStatus;
            found = true;
        }
    }

    if (found) {
        saveFile(logs, totalLogs, filepath); 
        cout << GREEN << "\n[+] SUCCESS: " << targetIP << " has been marked as " << newStatus << ".\n" << RESET;
        displaySummary(logs, totalLogs); 
        generateReport(logs, totalLogs); 
    } else {
        cout << RED << "\n[-] ERROR: IP Address '" << targetIP << "' not found in logs.\n\n" << RESET;
    }
}

void saveFile(LogEntry logs[], int totalLogs, string filepath) {
    ofstream file(filepath.c_str());
    if (file.is_open()) {
        for (int i = 0; i < totalLogs; i++) {
            file << logs[i].ipAddress << " [" << logs[i].timestamp << "] " 
                 << logs[i].action << " " << logs[i].status << " " 
                 << logs[i].ipStatus << "\n";
        }
        file.close();
    }
}
