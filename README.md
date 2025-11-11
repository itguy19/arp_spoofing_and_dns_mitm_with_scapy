# ARP Spoofing and DNS MITM with Scapy

In an isolated lab network, build Scapy-based tools to perform ARP spoofing to become a Man-in-the-Middle and implement selective DNS spoofing to redirect victims to attacker-controlled pages. Capture evidence, analyse intercepted traffic, and propose mitigations.

## Project Setup Guide

This guide explains how to set up and run the project using a Python virtual environment (`venv`) and a `requirements.txt` file.

---

### 🧰 Prerequisites

Before you begin, make sure you have:

- **Python 3.8+** installed  
- **pip** (Python package installer)  
- (Optional) **Git**, if you are cloning the repository  

---

## 🚀 Setup Instructions

### 1. Create a Virtual Environment

Create a virtual environment named `venv`:

```bash
python -m venv venv
```

### 2. Activate the Virtual Environment

#### On Windows

```bash
venv\Scripts\activate
```

#### On macOS / Linux

```bash
source venv/bin/activate
```

Once activated, you should see `(venv)` at the start of your command prompt.

---

### 4. Install Dependencies

Install all required Python packages using the `requirements.txt` file:

```bash
pip install -r requirements.txt
```

✅ You’re all set! Your environment should now be ready to run the project.

---

### 5. Deactivate the Virtual Environment

When you’re done working:

```bash
deactivate
```

---

## Running scripts

```bash
 sudo python3 arp_spoof.py -t 10.0.2.15 -g 10.0.2.7 -i eth0
 sudo python3 traffic_interceptor.py
 sudo python3 dns_spoofer.py
```
