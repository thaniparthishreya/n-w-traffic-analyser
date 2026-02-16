# Network Traffic Analyzer 

A Python-based network traffic analysis tool that detects potential DDoS and malicious traffic patterns using statistical analysis and visualization.

This project analyzes network flow datasets and generates insights, risk scores, and attack classifications.

---

## Project Overview

This tool performs:

• Network traffic visualization  
• Risk scoring of suspicious flows  
• Heuristic attack classification  
• Traffic spike detection  
• Port targeting analysis  
• Automated alert reporting  

The goal is to simulate a lightweight network monitoring and DDoS detection system.

---

## Detection Features

### Risk Score Engine
Each network flow is scored using:
- SYN Flag Count
- Flow Packets per second
- Flow Bytes per second

High-risk flows are exported automatically.

### Attack Type Classification
Flows are categorized into:
- SYN Flood
- UDP / Traffic Flood
- Port Scan
- Benign Traffic

### Network Traffic Insights
The analyzer generates:

Charts:
- Traffic distribution
- Packet rate histogram
- Top targeted ports
- Attack type distribution
- Traffic spike time series
- Ports targeted by attack type
- Port vs attack heatmap

Reports:
- `high_risk_flows.csv`
- `all_flows_with_attack_type.csv`

---

## Output Example

All charts and reports are saved in the **outputs/** folder after execution.

---

## Tech Stack

Python  
Pandas  
Matplotlib  
Seaborn  

---

## Install dependencies

pip install pandas matplotlib seaborn

---

## Example Console Output

ALERT SUMMARY:  
High Risk Flows: XXXX  
Attack Type Counts:  
SYN Flood XXXX  
UDP/Traffic Flood XXXX  
Port Scan XXXX  
Benign XXXX

---

## Future Improvements

- Real-time packet capture
- Email/alert integration
- Streamlit dashboard 

---

## Author

Shreya Thaniparthi
