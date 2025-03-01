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
   git clone https://github.com/siyannon/python_tcpscan/tcp-syn-port-scanner.git
   cd tcp-syn-port-scanner
   ```

## Usage
Run the script with Python and specify the target IP and ports to scan. The script supports both single port scanning and port range scanning.

## Command Syntax
```python
python tcpscan.py [-h] -ip IP [-p PORT | -r RANGE] [-t TIMEOUT]
```
###### Options
- -ip IP: Target IP address (e.g., 192.168.192.227) (required)
- -p PORT: Single port to scan (e.g., 80)
- -r RANGE: Port range to scan (e.g., 80-100)
- -t TIMEOUT: Timeout in seconds (default: 20)
- -h: Show help message
Note: Either -p or -r must be specified, but not both.

## Examples
###### Scan a single port:
```bash
python tcpscan.py -ip 192.168.192.227 -p 80 -t 10
```
Output:
```
Scanning 192.168.192.227 with timeout 10s...
Port 80 is open
Scan completed.
```
![Uploading 屏幕截图(900).png…]()

###### Scan a range of ports:
```python
python script.py -ip 192.168.192.227 -r 80-85 -t 15
```
Output:
```
Scanning 192.168.192.227 with timeout 15s...
Port 80 is open
Port 81 is closed
Port 82 is closed or filtered (no response)
...
Scan completed.
```
![屏幕截图(898)](https://github.com/user-attachments/assets/6c1fa955-45ee-45f1-a6a8-d8a25ede9cda)

###### Show help:
```python
python script.py -h
```
![屏幕截图(897)](https://github.com/user-attachments/assets/335e4116-a886-4c9c-b452-be6fd2637abd)

## Notes
- The script requires root/admin privileges to send raw packets via Scapy.
- Ensure the target IP is reachable within your network.
- Scanning large port ranges may take significant time; adjust the timeout as needed.
- Ports must be between 1 and 65535.
