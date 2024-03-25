from scapy.all import sniff

def packet_callback(packet):
    # Check if packet has IP layer
    if packet.haslayer('IP'):
        # Extract relevant information
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        proto = packet['IP'].proto

        # Display information
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {proto}")

        # Check if packet has payload
        if packet.haslayer('Raw'):
            payload = packet['Raw'].load
            print("Payload:", payload.hex())

# Sniff packets
print("Starting packet sniffer...")
sniff(prn=packet_callback, count=10)  # Sniff 10 packets
