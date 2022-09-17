import nmap


def scan_hosts(ips: list) -> dict:
    """Gets the list of ip to scan, returns list of opened ports assign to specific ip address
    Uses nmap (need to be imported), method PortScaner().
    Run as root

    Args:
        ips (list): list of ip to scan

    Returns:
        dict: key: ip, value: list of opened ports
    """
    START_PORT = 21
    END_PORT = 80
    print("Scanning...")
    scanner = nmap.PortScanner()
    hosts_open_ports = {}
    for ip in ips:
        address = str(ip)
        ports_open = []
        for port in range (START_PORT, END_PORT + 1):
            resp = scanner.scan(address, str(port))
            resp = resp['scan'][address]['tcp'][port]['state']
            if resp == "open":
                print(f'Host {address} port {port} is {resp}.')
                ports_open.append(port)
            else:   #prints out closed ports
                print(f'Host {address} port {port} is {resp}.')
        hosts_open_ports[address] = ports_open
    return hosts_open_ports

# tests with scanning. Hosts with adresses below must be active
# warning - port can be filtered (80/http)
# print(scan_hosts(['192.168.10.107']))
