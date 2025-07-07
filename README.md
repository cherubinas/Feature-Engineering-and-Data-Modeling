# Cyberattack Detection via Network Traffic Analysis & Machine Learning
This project simulates a Command and Control (C2) cyberattack in a virtual environment, captures network traffic, extracts relevant features, and trains a Random Forest machine learning model to detect malicious behavior.

It was developed as a learning tool for understanding network-based threat detection using packet captures and ML.

# Authors
 - Evelina Kabišaitytė
- Ugnė Vaičiūnaitė
- Martynas Lipskis
- Kamilė Norkutė

Supervised at Vilnius University, MIF.

 # Project Structure

- `attacker_vm/` – Scripts and configs for attacker VM  
- `victim_vm/` – Bash backdoor script for victim VM  
- `pcap_samples/` – Captured `.pcap` files (`Victim.pcap`, `Attacker.pcap`)  
- `feature_extraction/` – Feature engineering scripts  
- `model/` – Training, saved model, and evaluation  
- `run.py` – Entry point: applies model to new `.pcap` files  
- `README.md` – Project overview (this file)  
- `requirements.txt` – Python dependencies  



# Project Setup
1. Virtual Machine Setup (via OpenNebula)
Launch two VMs:

- Attacker VM

- Victim VM

2. Install Tools
On both machines:

```bash
sudo apt update && sudo apt install tcpdump curl
```

3. Run Tcpdump
Start capturing traffic on both machines:

```bash
sudo tcpdump -i eth0 -w Victim.pcap &
sudo tcpdump -i eth0 -w Attacker.pcap &
```
4. Simulate C2 Attack
   
On the Attacker VM, start a Python HTTP server (on port 80) to serve and receive command data.

 On the Victim VM, run the bash reverse shell script that:

  - Sends GET requests to /command
  
 - Executes commands
  
- Sends results via POST to /result
  
- Captured traffic mimics a C2 communication channel over HTTP.

# Data Collection
After running the attack:

Stop tcpdump using Ctrl+C.

Transfer .pcap files to your local machine using scp:
```bash
scp -P <PORT> <user>@<vm_ip>:~/Victim.pcap ./pcap_samples/
```
# Feature Engineering
Features extracted from .pcap files include:

- URI paths (e.g., /command, /result)

 - HTTP methods (GET, POST)

- URI string length

- Time gaps between requests per IP

Labeled data:

- Malicious (1) — C2 patterns

- Benign (0) — everything else

# Model Training
A Random Forest classifier is trained on the extracted features.

Preprocessing includes standardization (StandardScaler) for time-based features.

Run training:

```bash
python train_model.py
```
Apply model to new .pcap data:

```bash
python run.py --input new_capture.pcap
```
#  Results
Flags C2-like behavior using HTTP request patterns

Produces detailed predictions including:

- Source/Destination IPs

- HTTP method

- URI

- Timing features

- Generalizes well to unseen traffic

# Example output:

```json

{
  "src_ip": "10.0.0.2",
  "dst_ip": "10.0.0.1",
  "uri": "/command",
  "method": "GET",
  "time_since_last_request": 3.0,
  "prediction": "malicious"
}
```
# Requirements

- scikit-learn
- pandas
- numpy
- pyshark
- joblib
  
Install with:
```bash
pip install -r requirements.txt
```

