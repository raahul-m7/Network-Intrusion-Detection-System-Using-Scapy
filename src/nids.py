from scapy.all import *
from nids_rules import *
import keyboard
import time

def detect_events(packet, custom_rules):
    rules = [
        rule_port_scan,
        rule_malicious_payload,
        rule_suspicious_traffic_pattern,
        rule_dns_query_anomalies,
        rule_unusual_outbound_traffic,
        rule_arp_spoofing,
        rule_dns_to_google,
        rule_ntp_traffic,
        rule_gateway_to_subnet,
        rule_udp_packet_sent
    ]
    rules.extend(custom_rules)

    for rule in rules:
        matched, description = rule(packet)
        if matched:
            print("Alert: {}".format(description))
            print(packet.summary())

def add_custom_rule(rule_string, custom_rules):
    try:
        # Split the rule string into its components
        components = rule_string.split()

        # Extract rule components
        rule_action = components[0]
        rule_protocol = components[1]
        rule_src_ip = components[2]
        rule_src_port = components[3]
        rule_flow = components[4]
        rule_dst_ip = components[5]
        rule_dst_port = components[6]
        rule_message = ' '.join(components[7:])  # Message may contain spaces, so join the remaining components

        # Add the custom rule to the rules list
        custom_rule = lambda packet: (True, rule_message) if (
            packet.haslayer(rule_protocol) and
            (rule_src_ip == 'any' or packet['IP'].src == rule_src_ip) and
            (rule_dst_ip == 'any' or packet['IP'].dst == rule_dst_ip) and
            (rule_src_port == 'any' or str(packet[TCP].sport) == rule_src_port) and
            (rule_dst_port == 'any' or str(packet[TCP].dport) == rule_dst_port)
        ) else (False, "")
        custom_rules.append(custom_rule)
        print("Custom rule added successfully.")
    except Exception as e:
        print("Error adding custom rule:", e)

def main():
    print("The network intrusion detection system has started")
    print("Scanning.........")
    custom_rules = []
    sniff(prn=lambda pkt: detect_events(pkt, custom_rules), store=0, iface="eth0")

    # Hotkey functionality to add custom rules
    print("Press Shift + C to add a custom rule or wait for 30 seconds to start scanning automatically.")
    start_time = time.time()
    while True:
        if keyboard.is_pressed('shift+c'):
            print("Enter the custom rule format:")
            print("action protocol src_ip src_port flow dst_ip dst_port message")
            print("Example: allow TCP 192.168.1.1 any any 192.168.2.1 any Allow all traffic from 192.168.1.1 to 192.168.2.1")
            rule_string = input("Enter the custom rule: ")
            add_custom_rule(rule_string, custom_rules)
            print("Press Shift + C to add another custom rule or wait for 30 seconds to start scanning automatically.")
            start_time = time.time()  # Reset the start time after each input
        elif time.time() - start_time >= 30:
            # Start scanning automatically after 30 seconds of inactivity
            print("Starting scanning...")
            break

if __name__ == "__main__":
    main()

