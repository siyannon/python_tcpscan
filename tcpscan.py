from scapy.all import *
import argparse
import sys

def scan_port(ip, port, timeout):
    try:
        # 创建TCP SYN数据包
        packet = IP(dst=ip) / TCP(sport=12345, dport=port, flags="S")
        
        # 发送数据包并等待响应
        resp = sr1(packet, timeout=timeout, verbose=0)
        
        # 检查响应
        if resp is None:
            print(f"Port {port} is closed or filtered (no response)")
        elif resp.haslayer(TCP):
            tcp_flags = resp.getlayer(TCP).flags
            if tcp_flags == 0x12:  # SYN+ACK
                # 发送RST关闭连接
                send(IP(dst=ip) / TCP(sport=12345, dport=port, flags="R"), verbose=0)
                print(f"Port {port} is open")
            elif tcp_flags == 0x14:  # RST
                print(f"Port {port} is closed")
            else:
                print(f"Port {port} returned unexpected flags: {hex(tcp_flags)}")
        else:
            print(f"Port {port} returned unexpected response")
            
    except PermissionError:
        print("Error: Please run the script with administrator/root privileges")
        return False
    except Exception as e:
        print(f"An error occurred while scanning port {port}: {str(e)}")
        return False
    return True

def scan_ports(ip, ports, timeout):
    print(f"Scanning {ip} with timeout {timeout}s...")
    for port in ports:
        scan_port(ip, port, timeout)
    print("Scan completed.")

def parse_port_range(port_range):
    try:
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            if start > end or start < 1 or end > 65535:
                raise ValueError("Invalid port range")
            return list(range(start, end + 1))
        else:
            port = int(port_range)
            if port < 1 or port > 65535:
                raise ValueError("Port must be between 1 and 65535")
            return [port]
    except ValueError as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="TCP SYN Port Scanner",
        usage="python %(prog)s [-h] -ip IP [-p PORT | -r RANGE] [-t TIMEOUT]"
    )
    
    parser.add_argument(
        "-ip",
        type=str,
        help="Target IP address (e.g., 192.168.192.227)",
        required=True
    )
    parser.add_argument(
        "-p",
        type=str,
        help="Single port to scan (e.g., 80)"
    )
    parser.add_argument(
        "-r",
        type=str,
        help="Port range to scan (e.g., 80-100)"
    )
    parser.add_argument(
        "-t",
        type=int,
        default=20,
        help="Timeout in seconds (default: 20)"
    )
    
    args = parser.parse_args()
    
    if not (args.p or args.r):
        print("Error: Either -p or -r must be specified")
        print("Use -h for help")
        sys.exit(1)
    if args.p and args.r:
        print("Error: Cannot use both -p and -r together")
        print("Use -h for help")
        sys.exit(1)
    
    if args.p:
        ports = parse_port_range(args.p)
    else:  # args.r
        ports = parse_port_range(args.r)
    
    scan_ports(args.ip, ports, args.t)

if __name__ == "__main__":
    main()
