import numpy as np
import json
import joblib
import mlflow
import mlflow.sklearn
from pathlib import Path
from xgboost import XGBClassifier
from sklearn.metrics import (f1_score, precision_score,
    recall_score, confusion_matrix, classification_report)

BASE_DIR  = Path('/home/funkea/SecOpsAI')
PROC_DIR  = BASE_DIR / 'data' / 'processed'
MODEL_DIR = BASE_DIR / 'models' / 'ml'
MODEL_DIR.mkdir(parents=True, exist_ok=True)

# ── Step 1: Load your teammate's data ────────────────────────
# These are the ONLY files you need from them. Nothing else.
X_train = np.load(PROC_DIR / 'X_train.npy')   # 82,332 flows × 38 features
X_test  = np.load(PROC_DIR / 'X_test.npy')    # 175,341 flows × 38 features
y_train = np.load(PROC_DIR / 'y_train.npy')   # 82,332 labels (0 or 1)
y_test  = np.load(PROC_DIR / 'y_test.npy')    # 175,341 labels (0 or 1)

print(f"Training: {X_train.shape[0]:,} flows, {X_train.shape[1]} features")
print(f"Testing:  {X_test.shape[0]:,} flows, {X_test.shape[1]} features")
print(f"Attack rate — train: {y_train.mean()*100:.1f}%  test: {y_test.mean()*100:.1f}%")

# ── Step 2: Handle class imbalance ───────────────────────────
# UNSW-NB15 has more normal flows than attacks.
# scale_pos_weight tells XGBoost: "pay more attention to attacks"
# because they are the minority class we care most about catching.
neg = (y_train == 0).sum()
pos = (y_train == 1).sum()
spw = neg / pos
print(f"\nClass imbalance: {neg:,} normal vs {pos:,} attacks")
print(f"scale_pos_weight = {spw:.2f}")

# ── Step 3: Connect to MLflow ─────────────────────────────────
# MLflow must be running: docker-compose up -d mlflow
mlflow.set_tracking_uri("http://localhost:5000")
mlflow.set_experiment("secopsai-detection")

# ── Step 4: Train and log everything to MLflow ───────────────
with mlflow.start_run(run_name="xgboost-v1"):

    model = XGBClassifier(
        n_estimators=300,        # number of trees
        max_depth=8,             # how deep each tree can go
        learning_rate=0.05,      # how much each tree corrects errors
        subsample=0.8,           # use 80% of training data per tree
        colsample_bytree=0.8,    # use 80% of features per tree
        scale_pos_weight=spw,    # handles class imbalance
        eval_metric='logloss',
        use_label_encoder=False,
        random_state=42,
        n_jobs=-1                # use all CPU cores
    )

    # X_train and X_test are ALREADY SCALED by your teammate
    # Do NOT scale again. Just pass them directly.
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],  # watch performance on test during training
        verbose=50                     # print progress every 50 trees
    )

    # ── Step 5: Measure performance on test data ──────────────
    # This MUST be the same X_test you used for the rule baseline.
    y_pred = model.predict(X_test)

    ml_f1  = f1_score(y_test, y_pred)
    ml_pre = precision_score(y_test, y_pred)
    ml_rec = recall_score(y_test, y_pred)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    ml_fpr = fp / (fp + tn)

    # ── Step 6: Log metrics to MLflow ────────────────────────
    mlflow.log_params({"n_estimators":300, "max_depth":8,
                       "learning_rate":0.05, "scale_pos_weight":round(spw,2)})
    mlflow.log_metrics({"f1":ml_f1, "precision":ml_pre,
                        "recall":ml_rec, "fpr":ml_fpr})
    mlflow.sklearn.log_model(model, "xgboost-detector")

    print("\n" + "=" * 55)
    print("XGBoost ML MODEL — FINAL METRICS")
    print("=" * 55)
    print(classification_report(y_test, y_pred, target_names=['Normal','Attack']))

    # ── Step 7: Load baseline and compare immediately ─────────
    with open(str(BASE_DIR/'models'/'baseline'/'baseline_metrics.json')) as f:
        baseline = json.load(f)
    
    improvement = ml_f1 - baseline["f1"]
    print(f"Rule Baseline F1: {baseline['f1']:.4f}")
    print(f"ML Model F1:      {ml_f1:.4f}")
    print(f"Improvement:      +{improvement:.4f} ({improvement*100:.1f}%)")
    print(f"15% target:       {'MET ✓' if improvement >= 0.15 else 'NOT MET ✗'}")

    # ── Step 8: Save model and metrics ───────────────────────
    joblib.dump(model, str(MODEL_DIR / 'xgboost_detector.pkl'))
    ml_metrics = {"f1":ml_f1,"precision":ml_pre,"recall":ml_rec,"fpr":ml_fpr,
                  "tp":int(tp),"fp":int(fp),"fn":int(fn),"tn":int(tn)}
    with open(str(MODEL_DIR / 'ml_metrics.json'), 'w') as f:
        json.dump(ml_metrics, f, indent=2)
    print("\nModel saved. Open localhost:5000 to see the run in MLflow.")
