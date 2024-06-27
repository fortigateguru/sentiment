import streamlit as st
import re
from collections import Counter
import ipaddress

def analyze_config(config_text, device_type):
    # Initialize variables
    ip_addresses = []
    access_lists = []
    routes = []
    hostname = ""
    interfaces = {}
    policies = []

    # Regular expressions for different patterns
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?'
    
    # Device-specific patterns
    if device_type == "Cisco":
        hostname_pattern = r'hostname\s+(\S+)'
        acl_pattern = r'access-list\s+(\d+)\s+(\w+)\s+(\S+)'
        route_pattern = r'ip route\s+(\S+)\s+(\S+)\s+(\S+)'
        interface_pattern = r'interface\s+(\S+)'
        ip_interface_pattern = r'ip address\s+(\S+)\s+(\S+)'
    elif device_type == "Fortigate":
        hostname_pattern = r'set hostname\s+"?(\S+)"?'
        policy_pattern = r'edit\s+(\d+)'
        policy_src_pattern = r'set srcaddr\s+(.+)'
        policy_dst_pattern = r'set dstaddr\s+(.+)'
        policy_action_pattern = r'set action\s+(\w+)'
        interface_pattern = r'config system interface'
        ip_interface_pattern = r'set ip\s+(\S+)\s+(\S+)'

    current_interface = None
    current_policy = None

    # Parse the configuration
    for line in config_text.split('\n'):
        # Extract IP addresses
        ip_addresses.extend(re.findall(ip_pattern, line))
        
        # Extract hostname
        hostname_match = re.search(hostname_pattern, line)
        if hostname_match:
            hostname = hostname_match.group(1)
        
        if device_type == "Cisco":
            # Extract access lists
            acl_match = re.search(acl_pattern, line)
            if acl_match:
                acl_num, action, rest = acl_match.groups()
                access_lists.append((acl_num, action, rest))
            
            # Extract routes
            route_match = re.search(route_pattern, line)
            if route_match:
                dest, mask, next_hop = route_match.groups()
                routes.append((dest, mask, next_hop))

            # Extract interfaces and their IPs
            if_match = re.search(interface_pattern, line)
            if if_match:
                current_interface = if_match.group(1)
                interfaces[current_interface] = []
            
            if current_interface:
                ip_if_match = re.search(ip_interface_pattern, line)
                if ip_if_match:
                    ip, mask = ip_if_match.groups()
                    interfaces[current_interface].append(f"{ip}/{mask}")

        elif device_type == "Fortigate":
            # Extract policies
            policy_match = re.search(policy_pattern, line)
            if policy_match:
                if current_policy:
                    policies.append(current_policy)
                current_policy = {"id": policy_match.group(1), "src": [], "dst": [], "action": ""}
            
            if current_policy:
                src_match = re.search(policy_src_pattern, line)
                if src_match:
                    current_policy["src"] = src_match.group(1).split()
                
                dst_match = re.search(policy_dst_pattern, line)
                if dst_match:
                    current_policy["dst"] = dst_match.group(1).split()
                
                action_match = re.search(policy_action_pattern, line)
                if action_match:
                    current_policy["action"] = action_match.group(1)

            # Extract interfaces and their IPs
            if re.search(interface_pattern, line):
                current_interface = True
            elif current_interface and line.strip() == 'end':
                current_interface = None
            
            if current_interface:
                ip_if_match = re.search(ip_interface_pattern, line)
                if ip_if_match:
                    ip, mask = ip_if_match.groups()
                    interface_name = "Unknown"  # You might want to extract the actual interface name
                    interfaces[interface_name] = interfaces.get(interface_name, []) + [f"{ip}/{mask}"]

    # Finalize the last policy if any
    if current_policy:
        policies.append(current_policy)

    # Analyze the extracted data
    unique_ip_addresses = set(ip_addresses)
    num_ip_addresses = len(unique_ip_addresses)
    num_access_lists = len(access_lists)
    most_common_route = Counter(routes).most_common(1)[0][0] if routes else "No routes found"

    # Identify unused IP addresses
    used_ips = set()
    for ips in interfaces.values():
        for ip in ips:
            used_ips.update(str(ip) for ip in ipaddress.ip_network(ip, strict=False))
    unused_ips = unique_ip_addresses - used_ips

    # Analyze complexity of access lists (for Cisco)
    acl_complexity = {}
    if device_type == "Cisco":
        for acl_num, _, _ in access_lists:
            if acl_num not in acl_complexity:
                acl_complexity[acl_num] = 1
            else:
                acl_complexity[acl_num] += 1

    return {
        "hostname": hostname,
        "num_ip_addresses": num_ip_addresses,
        "num_access_lists": num_access_lists,
        "most_common_route": most_common_route,
        "ip_addresses": list(unique_ip_addresses),
        "access_lists": access_lists,
        "routes": routes,
        "interfaces": interfaces,
        "unused_ips": list(unused_ips),
        "acl_complexity": acl_complexity,
        "policies": policies
    }

def main():
    st.title("Enhanced Network Configuration Analyzer")

    # File uploader
    uploaded_file = st.file_uploader("Choose a configuration file", type="txt")
    
    # Device type selector
    device_type = st.selectbox("Select device type", ["Cisco", "Fortigate"])

    if uploaded_file is not None:
        # Read and analyze the config file
        config_text = uploaded_file.getvalue().decode("utf-8")
        analysis = analyze_config(config_text, device_type)

        # Display results
        st.header("Analysis Results")
        st.write(f"Hostname: {analysis['hostname']}")
        st.write(f"Number of unique IP addresses: {analysis['num_ip_addresses']}")
        
        if device_type == "Cisco":
            st.write(f"Number of access lists: {analysis['num_access_lists']}")
            st.write(f"Most common route: {analysis['most_common_route']}")
        elif device_type == "Fortigate":
            st.write(f"Number of firewall policies: {len(analysis['policies'])}")

        # Expandable sections for detailed information
        with st.expander("View all IP addresses"):
            st.write(", ".join(analysis['ip_addresses']))

        with st.expander("View unused IP addresses"):
            st.write(", ".join(analysis['unused_ips']))

        with st.expander("View interfaces and their IPs"):
            for interface, ips in analysis['interfaces'].items():
                st.write(f"{interface}: {', '.join(ips)}")

        if device_type == "Cisco":
            with st.expander("View access lists"):
                for acl in analysis['access_lists']:
                    st.write(f"ACL {acl[0]}: {acl[1]} {acl[2]}")

            with st.expander("View access list complexity"):
                for acl, count in analysis['acl_complexity'].items():
                    st.write(f"ACL {acl}: {count} rules")

            with st.expander("View routes"):
                for route in analysis['routes']:
                    st.write(f"Destination: {route[0]}, Mask: {route[1]}, Next Hop: {route[2]}")

        elif device_type == "Fortigate":
            with st.expander("View firewall policies"):
                for policy in analysis['policies']:
                    st.write(f"Policy {policy['id']}:")
                    st.write(f"  Source: {', '.join(policy['src'])}")
                    st.write(f"  Destination: {', '.join(policy['dst'])}")
                    st.write(f"  Action: {policy['action']}")

if __name__ == "__main__":
    main()
