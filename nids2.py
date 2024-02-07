from scapy.all import sniff, IP
from sklearn.ensemble import IsolationForest
import numpy as np
import socket
import random

# Global variable for data collection
training_data = []
test_data=[]
# Function to log data
def log_data(data, filename='data_file.txt'):
    with open(filename, 'a') as file:
        file.write(str(data) + "\n")

# Function to process each packet for training data collection
def collect_training_data(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        src_ip_int = int.from_bytes(socket.inet_aton(src_ip), 'big')
        dst_ip_int = int.from_bytes(socket.inet_aton(dst_ip), 'big')

        packet_data = [src_ip_int, dst_ip_int, protocol]
        training_data.append(packet_data)
    log_data(packet)  # Log packet data
    log_data("")

# Function to start packet sniffing for training data
def collect_data_for_training(packet_count):
    sniff(prn=collect_training_data, store=0, count=packet_count)

def get_packet(packet):
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        src_ip_int = int.from_bytes(socket.inet_aton(src_ip), 'big')
        dst_ip_int = int.from_bytes(socket.inet_aton(dst_ip), 'big')

        packet_data = [src_ip_int, dst_ip_int, protocol]
        test_data.append(packet_data)
    

        
# Function to train the model
def train_model(data):
    model = IsolationForest(contamination=0.1)
    model.fit(data)
    return model

# Function to simulate an attack
def simulate_attack(model):
    for _ in range(10):
        fake_src_ip = socket.inet_ntoa(random.getrandbits(32).to_bytes(4, 'big'))
        fake_dst_ip = socket.inet_ntoa(random.getrandbits(32).to_bytes(4, 'big'))
        fake_protocol = 255

        fake_packet_data = [int.from_bytes(socket.inet_aton(fake_src_ip), 'big'),
                            int.from_bytes(socket.inet_aton(fake_dst_ip), 'big'),
                            fake_protocol]

        log_data(fake_packet_data, 'attack_log.txt')  # Log simulated attack packet

        prediction = model.predict([fake_packet_data])
        if prediction == -1:
            log_data(f"Anomaly detected in simulated attack: {fake_packet_data}", 'attack_log.txt')

        sniff(prn=get_packet, store=0, count=1)
        if test_data:
            latest_packet_data = test_data[-1]  # Get the last packet data
            prediction = model.predict([latest_packet_data])  # Predict for the latest packet only
            if prediction == -1:
                log_data(f"Anomaly detected: {latest_packet_data}", 'attack_log.txt')
            else:
                log_data(f"No Anomaly detected in live: {latest_packet_data}", 'attack_log.txt')
        else:
            log_data("No valid packet data captured in live stream.", 'attack_log.txt')
        log_data("", 'attack_log.txt')

# Main function
if __name__ == "__main__":
    print("Collecting training data...")
    collect_data_for_training(500)  # Collect 500 packets for training

    print("Training model...")
    model = train_model(np.array(training_data))

    print("Simulating attack...")
    simulate_attack(model)

    print("Process completed.")
