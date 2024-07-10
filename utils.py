import streamlit as st
import requests
from bs4 import BeautifulSoup
import ssl
import socket
from datetime import datetime
import OpenSSL

def check_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        
        security_headers = {
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Not set'),
            'X-Frame-Options': headers.get('X-Frame-Options', 'Not set'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Not set'),
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not set'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Not set'),
            'Referrer-Policy': headers.get('Referrer-Policy', 'Not set')
        }
        
        return security_headers
    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}"

def check_cookies(url):
    try:
        response = requests.get(url)
        cookies = response.cookies
        
        cookie_info = []
        for cookie in cookies:
            cookie_info.append({
                'name': cookie.name,
                'secure': cookie.secure,
                'httponly': cookie.has_nonstandard_attr('httponly'),
                'samesite': cookie.get_nonstandard_attr('samesite', 'Not set')
            })
        
        return cookie_info
    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}"

def check_ssl_cert(hostname):
    try:
        cert = ssl.get_server_certificate((hostname, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        
        cert_info = {
            'subject': dict(x509.get_subject().get_components()),
            'issuer': dict(x509.get_issuer().get_components()),
            'version': x509.get_version(),
            'serial_number': x509.get_serial_number(),
            'not_before': datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ'),
            'not_after': datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        }
        
        return cert_info
    except Exception as e:
        return f"Error: {str(e)}"

st.title('Website Security Checker')

url = st.text_input('Enter the URL to check (include https://):')

if st.button('Check Security'):
    if url:
        st.header('Security Headers')
        headers = check_security_headers(url)
        if isinstance(headers, dict):
            for header, value in headers.items():
                st.write(f"{header}: {value}")
        else:
            st.write(headers)
        
        st.header('Cookies')
        cookies = check_cookies(url)
        if isinstance(cookies, list):
            for cookie in cookies:
                st.write(f"Name: {cookie['name']}")
                st.write(f"Secure: {cookie['secure']}")
                st.write(f"HttpOnly: {cookie['httponly']}")
                st.write(f"SameSite: {cookie['samesite']}")
                st.write('---')
        else:
            st.write(cookies)
        
        st.header('SSL Certificate')
        hostname = url.split('//')[1].split('/')[0]
        cert_info = check_ssl_cert(hostname)
        if isinstance(cert_info, dict):
            st.write(f"Subject: {cert_info['subject']}")
            st.write(f"Issuer: {cert_info['issuer']}")
            st.write(f"Version: {cert_info['version']}")
            st.write(f"Serial Number: {cert_info['serial_number']}")
            st.write(f"Not Before: {cert_info['not_before']}")
            st.write(f"Not After: {cert_info['not_after']}")
        else:
            st.write(cert_info)
    else:
        st.write('Please enter a URL to check.')
