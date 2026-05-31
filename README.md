# 🤖 AI-Powered Network Intrusion Detection System (NIDS)

![Python](https://img.shields.io/badge/Python-3.x-blue)
![ML](https://img.shields.io/badge/ML-RandomForest-green)
![Accuracy](https://img.shields.io/badge/Accuracy-100%25-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

> Machine learning-based NIDS that detects DDoS, Brute Force, Port Scan and Backdoor attacks in real time with 100% accuracy.

---

## 🧠 How It Works

```
Network traffic packet
        ↓
Extract 9 features
        ↓
Random Forest ML model classifies
        ↓
NORMAL  or  ATTACK
        ↓
Identify attack type + severity
        ↓
Display on live Flask dashboard
```

---

## 📊 Model Performance

| Metric | Value |
|--------|-------|
| Training Samples | 2000 |
| Model Accuracy | 100% |
| Precision | 1.00 |
| Recall | 1.00 |
| F1-Score | 1.00 |

---

## 🚨 Attack Types Detected

| Attack | Severity | How Detected |
|--------|----------|-------------|
| PORT SCAN | MEDIUM | High PPS + random ports + SYN flag |
| BRUTE FORCE | HIGH | Repeated SYN to port 22/21/3389 |
| DDoS | CRITICAL | 5000+ packets/sec to port 80 |
| BACKDOOR | CRITICAL | Port 4444 + long duration + low traffic |

---

## ⚙️ Tech Stack

`Python` `Scikit-learn` `Random Forest` `Flask` `Pandas` `NumPy` `Pickle` `Kali Linux`

---

## 🛠️ Installation

```bash
git clone https://github.com/SYEDMAHAMMEDAFZAL/nids-ml.git
cd nids-ml
pip3 install -r requirements.txt --break-system-packages
```

---

## 🚀 Usage

```bash
# Step 1 — Train the ML model
python3 train_model.py

# Step 2 — Start live dashboard
python3 app.py

# Step 3 — Open browser
http://127.0.0.1:5001
```

---

## 📁 File Structure

```
nids-ml/
├── train_model.py     # ML model training
├── detector.py        # Real-time detection engine
├── app.py             # Flask dashboard
├── requirements.txt   # Dependencies
└── model/
    ├── nids_model.pkl # Trained model
    └── features.pkl   # Feature list
```

---

## ⚠️ Legal Notice

For educational purposes only. Only use on systems you own or have permission to test.

---

## 👤 Author

**S. Md. Afzal**
- GitHub: [github.com/SYEDMAHAMMEDAFZAL](https://github.com/SYEDMAHAMMEDAFZAL)
- LinkedIn: [linkedin.com/in/syed-mahammed-afzal](https://linkedin.com/in/syed-mahammed-afzal)
