from scapy.all import sniff, send, IP
from sklearn.ensemble import IsolationForest
import numpy as np
import socket
import random

# Initialize the global model
model = None

# Global variable to store packet data for analysis
data = []

# Function to simulate an attack
def simulate_attack():
    fake_protocol = 255  # Reserved Protocol Number for experimentation
    fake_src_ip = socket.inet_ntoa(random.getrandbits(32).to_bytes(4, 'big'))
    fake_dst_ip = socket.inet_ntoa(random.getrandbits(32).to_bytes(4, 'big'))
    fake_packet = IP(src=fake_src_ip, dst=fake_dst_ip, proto=fake_protocol)
    send(fake_packet)

    # Convert fake IP addresses to integers and append to data
    fake_src_ip_int = int.from_bytes(socket.inet_aton(fake_src_ip), 'big')
    fake_dst_ip_int = int.from_bytes(socket.inet_aton(fake_dst_ip), 'big')
    fake_packet_data = [fake_src_ip_int, fake_dst_ip_int, fake_protocol]
    data.append(fake_packet_data)

    # Predict using the model
    if model:
        prediction = model.predict([fake_packet_data])
        if prediction == -1:
            handle_anomaly_detected(fake_src_ip, fake_dst_ip, fake_protocol)

# Function for Anomaly Detection using Isolation Forest
def train_model(data):
    global model
    model = IsolationForest(contamination=0.1)
    model.fit(data)

# Function for Signature-Based Detection
def signature_based_detection(protocol):
    known_signatures = [255,6]  # Assuming protocol numbers are integers
    return protocol in known_signatures

# Function to handle Anomaly Detection
def handle_anomaly_detected(src_ip, dst_ip, protocol):
    print(f"Anomaly detected! Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol}")
    log_incident(src_ip, dst_ip, protocol, "Anomaly")

# Function to handle Signature Detection
def handle_signature_detected(src_ip, dst_ip, protocol):
    print(f"Signature-based threat detected! Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol}")
    log_incident(src_ip, dst_ip, protocol, "Signature")

# Function to log incidents
def log_incident(src_ip, dst_ip, protocol, threat_type):
    with open('incident_log.txt', 'a') as log_file:
        log_file.write(f"{threat_type} - Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol}\n")

# Main function to process each packet
def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        src_ip_int = int.from_bytes(socket.inet_aton(src_ip), 'big')
        dst_ip_int = int.from_bytes(socket.inet_aton(dst_ip), 'big')

        packet_data = [src_ip_int, dst_ip_int, protocol]
        data.append(packet_data)

        # Check for signature-based threats
        if signature_based_detection(protocol):
            handle_signature_detected(src_ip, dst_ip, protocol)

# Function to start packet sniffing
def start_sniffing():
    sniff(prn=process_packet, store=0, count=250)

# Entry point of the script
if __name__ == "__main__":
    print("Starting NIDS...")
    start_sniffing()

    # Train the model after collecting data
    train_model(np.array(data))

    print("Simulating attack...")
    simulate_attack()

    print("Captured 250 packets. Stopping NIDS.")
