# DNSLookupSystem

A Python-based DNS lookup tool that implements a **custom DNS resolver from scratch** using UDP sockets, without relying on system-level DNS resolver libraries. This project demonstrates a low-level understanding of the DNS protocol, including packet construction, response parsing, timeout handling, and performance measurement.

---

## 🚀 Key Highlights

* Low-level DNS packet encoding and decoding
* Multi-interface access (CLI, GUI, Web)
* Performance benchmarking and comparison with system DNS
* Implemented DNSSEC for record authenticity and integrity.
* Clean, modular, and extensible codebase

---

## 🧰 Technology Stack

* **Programming Language:** Python 3
* **Networking:** UDP Sockets, DNS Protocol (RFC 1035)
* **Web Framework:** Flask
* **Desktop GUI:** Tkinter
* **Core Concepts:**

  * Computer Networks
  * Client–Server Architecture
  * Binary Data Encoding
  * Protocol Design

---

## ✨ Features

* Manual DNS query packet construction using binary encoding
* UDP-based DNS request/response handling
* Parsing of DNS response sections:

  * Header
  * Question
  * Answer
* Supported DNS record types:

  * **A** (IPv4)
  * **AAAA** (IPv6)
  * **CNAME**
* DNS lookup latency measurement
* Timeout and exception handling
* Logging of DNS results and performance metrics
* Side-by-side comparison with system-level DNS resolution

---

## 📊 Performance Metrics

* Measures DNS lookup latency (in milliseconds)
* Logs response time and record details
* Compares custom resolver performance against system DNS resolution

---

## 🎯 Learning Outcomes

* Deep understanding of DNS protocol internals
* Hands-on experience with UDP socket programming
* Binary data manipulation and protocol parsing
* Building multi-interface applications from a single core logic
* Practical application of computer networking concepts

