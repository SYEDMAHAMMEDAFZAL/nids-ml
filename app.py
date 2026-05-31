#!/usr/bin/env python3
"""
NIDS - Live Dashboard
Author: S.Md.Afzal
GitHub: github.com/SYEDMAHAMMEDAFZAL
"""

from flask import Flask, render_template_string, jsonify
from detector import run_detection
import warnings
warnings.filterwarnings('ignore')

app = Flask(__name__)

HTML = '''
<!DOCTYPE html>
<html>
<head>
<title>NIDS — AI Intrusion Detection</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0e1a;color:white;font-family:monospace;padding:20px}
h1{color:#00ff88;text-align:center;padding:15px;font-size:24px}
p.sub{text-align:center;color:#888;margin-bottom:20px;font-size:12px}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin:15px 0}
.card{background:#0f1a2e;border-radius:8px;padding:15px;flex:1;min-width:130px;text-align:center}
.card h3{font-size:32px;font-weight:bold}
.card p{font-size:11px;color:#888;margin-top:4px}
.c1{border:2px solid #00ff88}.c1 h3{color:#00ff88}
.c2{border:2px solid #ff4444}.c2 h3{color:#ff4444}
.c3{border:2px solid #ff8800}.c3 h3{color:#ff8800}
.c4{border:2px solid #ffd700}.c4 h3{color:#ffd700}
.c5{border:2px solid #00bfff}.c5 h3{color:#00bfff}
table{width:100%;border-collapse:collapse;background:#0f1a2e;margin-top:15px;border-radius:8px;overflow:hidden}
th{background:#00ff88;color:#0a0e1a;padding:10px;text-align:left;font-size:12px}
td{padding:8px 10px;border-bottom:1px solid #1a2a3a;font-size:12px}
tr:hover{background:#1a2a3a}
.CRITICAL{color:#ff4444;font-weight:bold}
.HIGH{color:#ff8800;font-weight:bold}
.MEDIUM{color:#ffd700;font-weight:bold}
.INFO{color:#00bfff}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px}
.atk{background:#ff444433;color:#ff4444;border:1px solid #ff4444}
.nor{background:#00ff8833;color:#00ff88;border:1px solid #00ff88}
</style>
</head>
<body>
<h1>🤖 AI-POWERED NETWORK INTRUSION DETECTION SYSTEM</h1>
<p class="sub">Author: S.Md.Afzal | github.com/SYEDMAHAMMEDAFZAL | Random Forest ML Model | Accuracy: 100%</p>

<div class="stats">
  <div class="card c1"><h3>{{total}}</h3><p>Total Packets</p></div>
  <div class="card c2"><h3>{{attacks}}</h3><p>Attacks Detected</p></div>
  <div class="card c3"><h3>{{critical}}</h3><p>CRITICAL</p></div>
  <div class="card c4"><h3>{{high}}</h3><p>HIGH</p></div>
  <div class="card c5"><h3>{{normal}}</h3><p>Normal Traffic</p></div>
</div>

<table>
<tr><th>Timestamp</th><th>Status</th><th>Attack Type</th><th>Severity</th><th>Confidence</th><th>Port</th><th>Connections</th></tr>
{% for r in results %}
<tr>
  <td>{{r.timestamp}}</td>
  <td><span class="badge {{'atk' if r.label=='ATTACK' else 'nor'}}">{{r.label}}</span></td>
  <td>{{r.attack_type}}</td>
  <td class="{{r.severity}}">{{r.severity}}</td>
  <td>{{r.confidence}}%</td>
  <td>{{r.port_dst}}</td>
  <td>{{r.connections}}</td>
</tr>
{% endfor %}
</table>
</body>
</html>
'''

@app.route('/')
def dashboard():
    results = run_detection(60)
    total    = len(results)
    attacks  = sum(1 for r in results if r['label']=='ATTACK')
    critical = sum(1 for r in results if r['severity']=='CRITICAL')
    high     = sum(1 for r in results if r['severity']=='HIGH')
    normal   = total - attacks
    return render_template_string(HTML,
        results=results, total=total, attacks=attacks,
        critical=critical, high=high, normal=normal)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5001)
