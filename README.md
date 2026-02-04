# DNSLookupSystem

A Python-based DNS lookup tool that implements a **custom DNS resolver from scratch** using UDP sockets, without relying on system-level DNS resolver libraries. This project demonstrates a low-level understanding of the DNS protocol, including packet construction, response parsing, timeout handling, and performance measurement.

The resolver is accessible through **three interfaces**:

* Command Line Interface (CLI)
* Tkinter-based Desktop GUI
* Flask-based Web Application

---

## 🚀 Key Highlights

* Fully custom DNS resolver (no `socket.gethostbyname` or system resolvers)
* Low-level DNS packet encoding and decoding
* Multi-interface access (CLI, GUI, Web)
* Performance benchmarking and comparison with system DNS
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
* Multiple user interfaces:

  * CLI
  * Flask Web Application
  * Tkinter Desktop Application

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

---

⚠️ Limitations & Drawbacks

* The resolver does not perform full recursive DNS resolution (root → TLD → authoritative servers); it relies on public DNS servers for final resolution.
* DNS caching is not implemented, resulting in repeated network queries for identical domains and increased lookup latency.
* Limited DNS record support: only A, AAAA, and CNAME records are parsed. Other common records such as MX, NS, TXT, SOA, and PTR are not currently supported.
* DNS response parsing is intentionally minimal and does not fully handle compressed name pointers in all edge cases.
* No DNSSEC validation is performed, making the resolver susceptible to spoofed or tampered DNS responses.
* The implementation is single-threaded and synchronous, which limits scalability under concurrent lookup requests.
* Error handling primarily addresses basic network failures and timeouts; detailed DNS error codes (RCODEs) are not fully interpreted.
* Logging is file-based without rotation or structured logging, which may result in unbounded log growth over time.
* The project is not intended for production use and is designed strictly for educational and demonstrative purposes.

