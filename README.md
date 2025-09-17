# 🔎 Mini Port & Service Scanner
![Tests](https://github.com/JDhat2002/Port-Service-Scanner-Mini-Nmap-Clone/actions/workflows/python-tests.yml/badge.svg)


A lightweight **asynchronous TCP port scanner** (mini Nmap clone) built in Python.  
Perfect for learning networking fundamentals, concurrency, and banner grabbing.

---

## 🚀 Features
- ⚡ Async TCP connect scanning with `asyncio`
- 🔑 Service detection (based on port + simple banner grab)
- 📊 Exports results in **JSON** and **CSV**
- 🎯 Configurable: custom ports, ranges, timeouts, concurrency
- 🖥️ CLI-first, with future GUI support (Streamlit)

---

## 📥 Installation
Clone the repo and install requirements:
```bash
git clone https://github.com/<your-username>/port_scanner.git
cd port_scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
