# TCP SYN Port Scanner

A simple TCP SYN port scanner built with Python and Scapy. This tool allows you to scan a target IP for open, closed, or filtered ports using TCP SYN packets.

## Features

- Scan a single port or a range of ports
- Customizable timeout for scanning
- Detailed port status reporting (open, closed, or filtered)
- Command-line interface with argument parsing

## Requirements

- Python 3.x
- Scapy library (`pip install scapy`)
- Administrator/root privileges (for sending raw packets)

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/your-username/tcp-syn-port-scanner.git
   cd tcp-syn-port-scanner
