import streamlit as st
import re
from collections import Counter
import ipaddress
import pandas as pd
import plotly.express as px
from streamlit_extras.switch_page_button import switch_page
from streamlit_extras.colored_header import colored_header
from streamlit_extras.add_vertical_space import add_vertical_space

# Set page config for a wider layout
st.set_page_config(layout="wide", page_title="Network Config Analyzer", page_icon="🌐")

# Custom CSS for a more modern look
st.markdown("""
<style>
    .stApp {
        background-color: #f0f2f6;
    }
    .stButton>button {
        background-color: #4CAF50;
        color: white;
    }
    .stTextInput>div>div>input {
        background-color: #fff;
    }
    .stSelectbox>div>div>select {
        background-color: #fff;
    }
</style>
""", unsafe_allow_html=True)

# The analyze_config function remains the same as in the previous version

def main():
    colored_header(label="Network Configuration Analyzer", description="Analyze your network device configurations", color_name="green-70")
    add_vertical_space(2)

    col1, col2 = st.columns([2, 1])

    with col1:
        # File uploader
        uploaded_file = st.file_uploader("Choose a configuration file", type="txt")

    with col2:
        # Device type selector
        device_type = st.selectbox("Select device type", ["Cisco", "Fortigate"])

    if uploaded_file is not None:
        try:
            # Read and analyze the config file
            config_text = uploaded_file.getvalue().decode("utf-8")
            analysis = analyze_config(config_text, device_type)

            # Display results
            st.header("Analysis Results")

            # Create three columns for key metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Hostname", analysis['hostname'])
            with col2:
                st.metric("Unique IP Addresses", analysis['num_ip_addresses'])
            with col3:
                if device_type == "Cisco":
                    st.metric("Access Lists", analysis['num_access_lists'])
                elif device_type == "Fortigate":
                    st.metric("Firewall Policies", len(analysis['policies']))

            add_vertical_space(2)

            # Tabs for different sections
            tab1, tab2, tab3, tab4 = st.tabs(["IP Addresses", "Interfaces", "Access Lists/Policies", "Routes"])

            with tab1:
                # IP address analysis
                st.subheader("IP Address Analysis")
                ip_df = pd.DataFrame({
                    'IP Address': analysis['ip_addresses'],
                    'Status': ['Used' if ip not in analysis['unused_ips'] else 'Unused' for ip in analysis['ip_addresses']]
                })
                fig = px.pie(ip_df, names='Status', title='IP Address Usage')
                st.plotly_chart(fig)
                st.dataframe(ip_df)

            with tab2:
                # Interface analysis
                st.subheader("Interface Analysis")
                for interface, ips in analysis['interfaces'].items():
                    st.write(f"**{interface}**: {', '.join(ips)}")

            with tab3:
                if device_type == "Cisco":
                    st.subheader("Access List Analysis")
                    acl_df = pd.DataFrame(analysis['access_lists'], columns=['ACL Number', 'Action', 'Details'])
                    st.dataframe(acl_df)
                    
                    # ACL complexity chart
                    complexity_df = pd.DataFrame.from_dict(analysis['acl_complexity'], orient='index', columns=['Rule Count']).reset_index()
                    complexity_df.columns = ['ACL Number', 'Rule Count']
                    fig = px.bar(complexity_df, x='ACL Number', y='Rule Count', title='ACL Complexity')
                    st.plotly_chart(fig)
                elif device_type == "Fortigate":
                    st.subheader("Firewall Policy Analysis")
                    for policy in analysis['policies']:
                        st.write(f"**Policy {policy['id']}**:")
                        st.write(f"  Source: {', '.join(policy['src'])}")
                        st.write(f"  Destination: {', '.join(policy['dst'])}")
                        st.write(f"  Action: {policy['action']}")
                        st.write("---")

            with tab4:
                if device_type == "Cisco":
                    st.subheader("Route Analysis")
                    route_df = pd.DataFrame(analysis['routes'], columns=['Destination', 'Mask', 'Next Hop'])
                    st.dataframe(route_df)
                    st.write(f"Most common route: {analysis['most_common_route']}")

        except Exception as e:
            st.error(f"An error occurred while analyzing the configuration: {str(e)}")
            st.write("Please check if the uploaded file is a valid configuration file and try again.")

if __name__ == "__main__":
    main()
