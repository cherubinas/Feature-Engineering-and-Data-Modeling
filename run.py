import pyshark
import pandas as pd
import joblib
import argparse

def extract_features(pcap_file, scaler):
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

    df = pd.DataFrame(data)
    df = df.sort_values(by=["src_ip", "time"]).reset_index(drop=True)

    df["is_command"] = df["uri"].apply(lambda x: 1 if x == "/command" else 0)
    df["is_result"] = df["uri"].apply(lambda x: 1 if x == "/result" else 0)
    df["uri_length"] = df["uri"].apply(lambda x: len(str(x)))
    df["is_get"] = df["method"].apply(lambda x: 1 if x == "GET" else 0)
    df["is_post"] = df["method"].apply(lambda x: 1 if x == "POST" else 0)
    df["time_since_last_request"] = df.groupby("src_ip")["time"].diff().fillna(0)
    df["time_since_last_request"] = scaler.transform(df[["time_since_last_request"]])

    return df

def main(pcap_files):
    clf = joblib.load("rf_model.joblib")
    scaler = joblib.load("scaler.joblib")

    all_detections = []

    for pcap_file in pcap_files:
        print(f"\n--- Analyzing {pcap_file} ---")
        df = extract_features(pcap_file, scaler)
        features = df[["is_command", "is_result", "uri_length", "is_get", "is_post", "time_since_last_request"]]
        df["prediction"] = clf.predict(features)

        detections = df[(df["is_command"] == 1) | (df["is_result"] == 1) | (df["prediction"] == 1)]
        print(detections[["frame", "src_ip", "dst_ip", "method", "uri", "time", "time_since_last_request", "prediction"]])
        all_detections.append(detections)

    return pd.concat(all_detections) if all_detections else None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect C2 HTTP traffic in PCAPs using trained model")
    parser.add_argument("--pcaps", nargs="+", required=True, help="Path(s) to one or more PCAP files")
    args = parser.parse_args()

    main(args.pcaps)
