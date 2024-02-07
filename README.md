# README: Network Security IDS Implementation

## Overview

This repository houses a Python implementation of an Intrusion Detection System (IDS) aimed at enhancing network security. The system employs both anomaly and signature-based detection techniques, providing a proactive response to cyber threats.

## Functionality

The project consists of two scripts:

- `nids.py`: Responsible for real-time traffic analysis, anomaly detection, and logging network incidents.
- `nids2.py`: Dedicated to collecting network traffic data for training and refining the IDS model.

The IDS generates three essential log files:

1. `attack_log.txt`: Records details of simulated network attacks for system evaluation.
2. `data_file.txt`: Compiles real network traffic data for training and refining the IDS model.
3. `incident_log.txt`: Documents detected network incidents, including anomalies and known threat signatures.

## Importance

- **Efficient Anomaly Detection**: Utilizes the Isolation Forest algorithm for swift and accurate identification of anomalies.
- **Comprehensive Security Measures**: Incorporates both anomaly and signature-based detection techniques for robust security.
- **Real-time Monitoring**: Actively monitors potential threats through real-time traffic analysis.
- **System Refinement**: Gathers data for continuous training, ensuring the IDS remains effective and up-to-date with evolving network behaviors.

## Results

The IDS demonstrated high proficiency in detecting anomalies and signature-based threats during simulated attacks. Real-time traffic analysis efficiently distinguished between normal and anomalous activities, showcasing its practical applicability in real-world network security scenarios.

## Instructions

1. Run `nids.py` for real-time traffic analysis and anomaly detection.
2. Execute `nids2.py` to collect network traffic data for training the IDS model.

Feel free to explore and contribute to further enhance network security!
