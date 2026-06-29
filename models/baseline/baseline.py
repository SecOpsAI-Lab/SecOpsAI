import sys
!{sys.executable} -m pip install numpy pandas scikit-learn -q

import numpy as np
import pandas as pd
import json, os
from sklearn.metrics import (
    f1_score, precision_score, recall_score,
    confusion_matrix, classification_report
)
print("Imports successful")


DATA_DIR = "../data/processed"   # adjust this path if needed

X_test = np.load(f"{DATA_DIR}/X_test.npy")
y_test = np.load(f"{DATA_DIR}/y_test.npy")

with open(f"{DATA_DIR}/feature_names.json") as f:
    FEATURE_COLS = json.load(f)

print(f"X_test shape: {X_test.shape}")
print(f"y_test shape: {y_test.shape}")
print(f"Features loaded: {len(FEATURE_COLS)}")
print(f"Attack rate: {y_test.mean()*100:.1f}%")


# Print all features so we know exactly which names to use in rules
for i, name in enumerate(FEATURE_COLS):
    print(f"  [{i:2d}] {name}")



def idx(name):
    """Get column index for a feature name."""
    return FEATURE_COLS.index(name)
    
def apply_suricata_rules(X):
    """
    Simulate Suricata rule logic on pre-scaled UNSW-NB15 features.
    Returns: array of 0 (normal) or 1 (attack flagged)
    """
    n = len(X)
    predictions = np.zeros(n)   # start: everything is normal

    # ── RULE 1: C2 Beaconing ──────────────────────────────────
    # Suricata rule: same src->dst >10 times in 60s
    # Feature proxy: sjit (source jitter) — C2 traffic has
    # unnaturally LOW jitter because it beacons like clockwork.
    # After scaling: very low sjit = well below average = < -0.5
    c2_mask = X[:, idx('sjit')] < -0.5
    predictions[c2_mask] = 1
    print(f"Rule 1 (C2 Beaconing):       {c2_mask.sum():,} flows flagged")

    # ── RULE 2: Lateral Movement / Port Scan ──────────────────
    # Suricata rule: >30 SYN packets from one source in 10s
    # Feature proxy: high spkts (source packets) AND very short
    # duration — scanning sends many packets very quickly
    scan_mask = (X[:, idx('spkts')] > 1.5) & (X[:, idx('dur')] < -0.4)
    predictions[scan_mask] = 1
    print(f"Rule 2 (Lateral Movement):   {scan_mask.sum():,} flows flagged")

    # ── RULE 3: Data Exfiltration ─────────────────────────────
    # Suricata rule: large outbound bytes in a single session
    # Feature proxy: byte_ratio — much more sent than received.
    # Exfiltration sends data out (high sbytes) but receives little (low dbytes)
    exfil_mask = X[:, idx('byte_ratio')] > 2.5
    predictions[exfil_mask] = 1
    print(f"Rule 3 (Exfiltration):       {exfil_mask.sum():,} flows flagged")

    # ── RULE 4: DDoS / Flood ──────────────────────────────────
    # Suricata rule: abnormally high traffic rate
    # Feature proxy: rate (packets per second) very high
    ddos_mask = X[:, idx('rate')] > 3.0
    predictions[ddos_mask] = 1
    print(f"Rule 4 (DDoS/Flood):         {ddos_mask.sum():,} flows flagged")


    # ── RULE 5: DNS Tunnelling ────────────────────────────────
    # Suricata rule: DNS query names > 100 chars
    # Feature proxy: high source load (sload) with high ct_flw_http_mthd
    # (abnormal HTTP method counts = protocol abuse typical of tunnelling)
    tunnel_mask = (X[:, idx('sload')] > 2.0) & \
                  (X[:, idx('ct_flw_http_mthd')] > 1.5)
    predictions[tunnel_mask] = 1
    print(f"Rule 5 (DNS Tunnelling):     {tunnel_mask.sum():,} flows flagged")

    return predictions

print("=" * 55)
print("Running rule-based baseline on test data...")
print("=" * 55)
y_pred_rules = apply_suricata_rules(X_test)



# ── Calculate and display all metrics ────────────────────────────
baseline_f1  = f1_score(y_test, y_pred_rules)
baseline_pre = precision_score(y_test, y_pred_rules)
baseline_rec = recall_score(y_test, y_pred_rules)
tn, fp, fn, tp = confusion_matrix(y_test, y_pred_rules).ravel()
baseline_fpr = fp / (fp + tn)


print("\n" + "=" * 55)
print("RULE-BASED BASELINE — FINAL METRICS")
print("=" * 55)
print(f"F1 Score:            {baseline_f1:.4f}")
print(f"Precision:           {baseline_pre:.4f}  (when it fires, how often right?)")
print(f"Recall:              {baseline_rec:.4f}  (what % of attacks did it catch?)")
print(f"False Positive Rate: {baseline_fpr:.4f}  (how much noise?)")
print(f"\nConfusion Matrix:")
print(f"  Caught attacks (TP):          {tp:,}")
print(f"  Missed attacks (FN):          {fn:,}  ← rules miss these")
print(f"  False alarms (FP):            {fp:,}  ← noise / alert fatigue")
print(f"  Correctly ignored benign (TN):{tn:,}")
print(f"\nML model must achieve F1 > {baseline_f1 + 0.15:.4f} to meet 15% target")


os.makedirs("models/baseline", exist_ok=True)
metrics = {"f1":baseline_f1,"precision":baseline_pre,"recall":baseline_rec,"fpr":baseline_fpr,
           "tp":int(tp),"fp":int(fp),"fn":int(fn),"tn":int(tn)}
with open("models/baseline/baseline_metrics.json","w") as f:
    json.dump(metrics, f, indent=2)
print("Saved to models/baseline/baseline_metrics.json")