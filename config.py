import streamlit as st
import re
from collections import Counter
import ipaddress
import pandas as pd
import plotly.express as px
from streamlit_extras.switch_page_button import switch_page
from streamlit_extras.colored_header import colored_header
from streamlit_extras.add_vertical_space import add_vertical_space
import traceback

# Set page config for a wider layout
st.set_page_config(layout="wide", page_title="Network Config Analyzer", page_icon="🌐")

# Debug function
def debug_print(message):
    st.text(f"DEBUG: {message}")

# The analyze_config function remains the same as in the previous version

def main():
    try:
        debug_print("Starting main function")
        
        colored_header(label="Network Configuration Analyzer", description="Analyze your network device configurations", color_name="green-70")
        add_vertical_space(2)

        debug_print("Header added")

        col1, col2 = st.columns([2, 1])

        with col1:
            # File uploader
            uploaded_file = st.file_uploader("Choose a configuration file", type="txt")

        with col2:
            # Device type selector
            device_type = st.selectbox("Select device type", ["Cisco", "Fortigate"])

        debug_print(f"File uploaded: {uploaded_file is not None}, Device type: {device_type}")

        if uploaded_file is not None:
            try:
                # Read and analyze the config file
                config_text = uploaded_file.getvalue().decode("utf-8")
                debug_print("Config file read successfully")
                
                analysis = analyze_config(config_text, device_type)
                debug_print("Config analysis completed")

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

                debug_print("Metrics displayed")

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

                debug_print("IP address tab completed")

                # ... [rest of the tab content remains the same] ...

                debug_print("All tabs completed")

            except Exception as e:
                st.error(f"An error occurred while analyzing the configuration: {str(e)}")
                st.text("Traceback:")
                st.text(traceback.format_exc())
                debug_print(f"Error in file analysis: {str(e)}")

    except Exception as e:
        st.error(f"An unexpected error occurred: {str(e)}")
        st.text("Traceback:")
        st.text(traceback.format_exc())
        debug_print(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    main()
