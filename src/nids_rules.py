
def rule_dns_to_google(packet):
    return (packet.haslayer('UDP') and
            packet['UDP'].dport == 53 and
            (packet['IP'].dst == '8.8.8.8' or packet['IP'].dst == '8.8.8.4'),
            "DNS query to Google DNS server")

def rule_ntp_traffic(packet):
    return (packet.haslayer('UDP') and
            packet['UDP'].dport == 123,
            "NTP traffic")

def rule_gateway_to_subnet(packet):
    return (packet.haslayer('TCP') and
            packet['IP'].src == '192.168.0.1' and
            packet['IP'].dst.startswith('192.168.0.'),
            "Gateway to subnet traffic")

def rule_udp_packet_sent(packet):
    return (packet.haslayer('UDP'),
            "UDP packet sent")

def rule_port_scan(packet):
    return (packet.haslayer('TCP') and
            packet['TCP'].flags == 2,
            "Port Scan Detected")

def rule_malicious_payload(packet):
    # Detect SQL injection attempts
    if packet.haslayer('Raw'):
        raw_data = packet['Raw'].load.decode('utf-8', errors='ignore').lower()
        if "select" in raw_data and "from" in raw_data and "where" in raw_data:
            return True, "Possible SQL Injection Attempt"
    return False, ""

def rule_suspicious_traffic_pattern(packet):
    # Detect excessive failed login attempts
    if packet.haslayer('TCP') and packet['TCP'].dport == 22:
        if "authentication failed" in str(packet['Raw']).lower():
            return True, "Excessive Failed SSH Login Attempts"
    return False, ""

def rule_unusual_outbound_traffic(packet):
    # Detect outbound traffic on non-standard ports
    return (packet.haslayer('TCP') and
            packet['IP'].dst.startswith('192.168.') and
            packet['TCP'].dport not in [80, 443, 53, 22],
            "Unusual Outbound Traffic")

def rule_arp_spoofing(packet):
    if packet.haslayer('ARP'):
        arp_src_ip = packet['ARP'].psrc
        arp_dst_ip = packet['ARP'].pdst
        arp_src_mac = packet['ARP'].hwsrc
        arp_dst_mac = packet['ARP'].hwdst
        if arp_src_ip != arp_dst_ip and arp_src_mac != arp_dst_mac:
            return True, "Possible ARP Spoofing Detected"
    return False, ""

def rule_dns_query_anomalies(packet):
    if packet.haslayer('DNS') and packet['DNS'].qr == 0:  # Check if DNS query (qr=0)
        dns_query = packet['DNS']
        query_type = dns_query.qd.qtype
        query_length = len(dns_query.qd.qname)
        query_pattern = dns_query.qd.qname.decode('utf-8', errors='ignore').lower()

        # Define your anomaly detection logic here
        if query_type not in [1, 28]:  # Check for unusual query types (1: A, 28: AAAA)
            return (True, "Unusual DNS query type: {}".format(query_type))

        if query_length > 50:  # Check for unusually long query names
            return (True, "Unusually long DNS query name (length: {})".format(query_length))

        if 'example.com' in query_pattern:  # Check for specific patterns in the query name
            return (True, "DNS query contains 'example.com'")

    return (False, "")


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
