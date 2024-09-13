# Network Intrusion Detection System Using Scapy

A Python-based Network Intrusion Detection System (NIDS) that monitors real-time network traffic for suspicious patterns and anomalies using the Scapy library. This tool is customizable with user-defined rules for detecting specific network activities.

## Installation

1. Clone the repository:
  
   git clone https://github.com/<Your-Username>/Network-Intrusion-Detection-System-Using-Scapy.git

2.Navigate into the project directory:
 
   cd Network-Intrusion-Detection-System-Using-Scapy

3.Install the required dependencies:
  
   pip install -r requirements.txt

## Usage

1.Run the intrusion detection system:
  
   python src/nids.py

2.Add custom detection rules using the following format:

   action protocol src_ip src_port flow dst_ip dst_port message

## License
This project is licensed under the MIT License - see the LICENSE file for details.
