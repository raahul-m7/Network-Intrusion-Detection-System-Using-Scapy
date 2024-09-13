# Network Intrusion Detection System Using Scapy

A Python-based Network Intrusion Detection System (NIDS) that monitors real-time network traffic for suspicious patterns and anomalies using the Scapy library. This tool is customizable with user-defined rules for detecting specific network activities.

## Features
- Real-time network traffic monitoring
- Detection of anomalies like port scanning, SQL injection attempts, ARP spoofing
- Custom rule addition via hotkeys

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/<Your-Username>/Network-Intrusion-Detection-System-Using-Scapy.git

Install the required dependencies:
bash

pip install -r requirements.txt

Usage
Run the intrusion detection system:
bash

python src/nids.py

Add custom detection rules using:
bash

action protocol src_ip src_port flow dst_ip dst_port message

License
This project is licensed under the MIT License - see the LICENSE file for details.
markdown


### Step 4: Add `requirements.txt`
1. **Click "Add file"** > **"Create new file"**.
2. Name it `requirements.txt` and add:
   ```txt
   scapy
   keyboard
