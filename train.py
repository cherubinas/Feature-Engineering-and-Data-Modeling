import pyshark
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Opens the .pcap file using pyshark and filters only HTTP request packets. 
# Then collects URI path (/command, /result, etc.), HTTP method, source/destination IPs, packet/frame number, and the timestamp.
def load_http_traffic(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="http.request")
    data = []
    for pkt in cap:
        try:
            uri = pkt.http.request_uri
            method = pkt.http.request_method
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            frame_number = pkt.frame_info.number
            time = float(pkt.sniff_timestamp)

            data.append({
                "frame": int(str(frame_number)),
                "time": time,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "uri": uri,
                "method": method
            })
        except AttributeError:
            continue
    cap.close()
    return pd.DataFrame(data)

# Loads traffic from both the attacker and victim files and sorts all packets by source IP and time for behavioral features.
victim_df = load_http_traffic("Victim1.pcap")
attacker_df = load_http_traffic("Attacker1.pcap")
df = pd.concat([victim_df, attacker_df]).sort_values(by=["src_ip", "time"]).reset_index(drop=True)

# Feature Engineering : These steps add features that help the model understand the data
df["is_command"] = df["uri"].apply(lambda x: 1 if x == "/command" else 0) #Binary flags for known C2 paths
df["is_result"] = df["uri"].apply(lambda x: 1 if x == "/result" else 0)
df["uri_length"] = df["uri"].apply(lambda x: len(str(x))) #Total length of the URI string
df["is_get"] = df["method"].apply(lambda x: 1 if x == "GET" else 0) #Binary HTTP method indicators
df["is_post"] = df["method"].apply(lambda x: 1 if x == "POST" else 0)
df["time_since_last_request"] = df.groupby("src_ip")["time"].diff().fillna(0) #time gap between requests per IP

# C2-related URIs are labeled as malicious (1), others as benign (0)
df["label"] = df["uri"].apply(lambda x: 1 if x in ["/command", "/result"] else 0)

# Feature matrix and label 
X = df[["is_command", "is_result", "uri_length", "is_get", "is_post", "time_since_last_request"]]
y = df["label"]

# Scale timing
scaler = StandardScaler()
X.loc[:, "time_since_last_request"] = scaler.fit_transform(X[["time_since_last_request"]])

# Splits data for training and testing and trains the random forest on the training data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, stratify=y, random_state=42
)
clf = RandomForestClassifier()
clf.fit(X_train, y_train)

# Prints standard classification metrics like precision, recall, f1-score and the confusion matrix
preds = clf.predict(X_test)
print("\n--- Model Evaluation ---")
print(classification_report(y_test, preds))
print(confusion_matrix(y_test, preds))

# Displays all C2-labeled requests for inspection
print("\n--- Detected C2 Requests (/command or /result) ---")
suspicious = df[(df["is_command"] == 1) | (df["is_result"] == 1)]
print(suspicious[["frame", "src_ip", "dst_ip", "method", "uri", "time", "time_since_last_request", "label"]])

# Helps identify class imbalance issues that affect model performance
print("Train label distribution:", y_train.value_counts().to_dict())
print("Test label distribution:", y_test.value_counts().to_dict())
print(confusion_matrix(y_test, preds))

# Saves trained model and scaler for later use during detection
joblib.dump(clf, "rf_model.joblib")
joblib.dump(scaler, "scaler.joblib")
print("\nModel and scaler saved: rf_model.joblib, scaler.joblib")
