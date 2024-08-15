import nmap
import json
import os

def host_scan(network):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')  # -sn for ping scan
    active_hosts = []

    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            active_hosts.append(host)

    with open('active_hosts.json', 'w') as f:
        json.dump(active_hosts, f)

    return active_hosts

def port_scan(target):
    nm = nmap.PortScanner()
    
    if os.path.exists('active_hosts.json'):
        with open('active_hosts.json', 'r') as f:
            active_hosts = json.load(f)
    else:
        active_hosts = [target]

    all_ports = {}
    
    for host in active_hosts:
        nm.scan(host, arguments='-sS -sU -T4')  # -sS for TCP SYN scan, -sU for UDP scan
        open_ports = {port: proto for proto in nm[host].all_protocols() for port in nm[host][proto] if nm[host][proto][port]['state'] == 'open'}
        all_ports[host] = open_ports

    with open('open_ports.json', 'w') as f:
        json.dump(all_ports, f)
    
    return all_ports

def service_scan(target):
    nm = nmap.PortScanner()

    if os.path.exists('active_hosts.json'):
        with open('active_hosts.json', 'r') as f:
            active_hosts = json.load(f)
    else:
        active_hosts = [target]

    all_services = {}

    for host in active_hosts:
        if os.path.exists('open_ports.json'):
            with open('open_ports.json', 'r') as f:
                open_ports = json.load(f).get(host, [])
        else:
            open_ports = []
            nm.scan(host, arguments='-sS -sU -T4')
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    if nm[host][proto][port]['state'] == 'open':
                        open_ports.append(port)

        nm.scan(host, arguments='-sV')
        services = {}
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                if port in open_ports and nm[host][proto][port]['state'] == 'open':
                    services[port] = {
                        'protocol': proto.upper(),
                        'service': nm[host][proto][port]['name']
                    }

        # If no services are found, set the message
        if not services:
            return False

        all_services[host] = services

    with open('services.json', 'w') as f:
        json.dump(all_services, f, indent=4)

    return all_services

def os_detection(target):
    nm = nmap.PortScanner()

    if os.path.exists('active_hosts.json'):
        with open('active_hosts.json', 'r') as f:
            active_hosts = json.load(f)
    else:
        active_hosts = [target]

    os_info = {}

    for host in active_hosts:
        nm.scan(host, arguments='-O')  # -O for OS detection
        os_type = nm[host]['osmatch'][0]['osclass'][0]['osfamily']
        os_version = nm[host]['osmatch'][0]['osclass'][0]['osgen']
        os_info[host] = {'os': os_type, 'version': os_version}

    with open('os_detection.json', 'w') as f:
        json.dump(os_info, f)
    
    return os_info