import streamlit as st
import re
from collections import Counter
import ipaddress

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_network(network):
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False

def analyze_config(config_text, device_type):
    # ... [previous code remains the same] ...

    # Analyze the extracted data
    unique_ip_addresses = set(ip for ip in ip_addresses if is_valid_ip(ip))
    num_ip_addresses = len(unique_ip_addresses)
    num_access_lists = len(access_lists)
    most_common_route = Counter(routes).most_common(1)[0][0] if routes else "No routes found"

    # Identify unused IP addresses
    used_ips = set()
    for ips in interfaces.values():
        for ip in ips:
            if is_valid_network(ip):
                used_ips.update(str(ip) for ip in ipaddress.ip_network(ip, strict=False))
            elif is_valid_ip(ip):
                used_ips.add(ip)
    unused_ips = unique_ip_addresses - used_ips

    # ... [rest of the function remains the same] ...

def main():
    st.title("Enhanced Network Configuration Analyzer")

    # File uploader
    uploaded_file = st.file_uploader("Choose a configuration file", type="txt")
    
    # Device type selector
    device_type = st.selectbox("Select device type", ["Cisco", "Fortigate"])

    if uploaded_file is not None:
        try:
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

            # ... [rest of the display code remains the same] ...

        except Exception as e:
            st.error(f"An error occurred while analyzing the configuration: {str(e)}")
            st.write("Please check if the uploaded file is a valid configuration file and try again.")

if __name__ == "__main__":
    main()
