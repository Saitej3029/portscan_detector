#!/usr/bin/env python3
"""
Port Scan Detector - A tool to detect and respond to port scanning attempts
using Wireshark/tshark as the packet capture engine.

This tool monitors network traffic for port scanning patterns and automatically
implements defensive measures including firewalls, port knocking, honeypots,
tarpitting, rate limiting, and Fail2Ban integration.
"""

import os
import sys
import argparse
import subprocess
import re
import time
import smtplib
import logging
import json
import threading
import ipaddress
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from collections import defaultdict, Counter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("port_scan_detector.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("PortScanDetector")

class PortScanDetector:
    def __init__(self, interface, email, config_file="config.json"):
        self.interface = interface
        self.admin_email = email
        self.config_file = config_file
        self.load_config()

        # State tracking
        self.connection_attempts = defaultdict(list)  # IP -> list of (timestamp, port)
        self.blocked_ips = set()
        self.honeypot_hits = defaultdict(int)  # IP -> count
        self.tarpit_ips = set()
        self.rate_limited_ips = set()
        
        # Port knocking sequence and state
        self.port_knock_sequence = self.config["port_knocking"]["sequence"]
        self.port_knock_state = defaultdict(list)  # IP -> list of ports knocked
        self.port_knock_timeout = self.config["port_knocking"]["timeout"]
        
        # Initialize components
        self.initialize_firewall()
        self.setup_honeypots()
        self.configure_tarpitting()
        self.configure_rate_limiting()
        self.configure_fail2ban()
        
        logger.info(f"Port Scan Detector initialized on interface {interface}")
        logger.info(f"Alerts will be sent to {email}")

    def load_config(self):
        """Load configuration from JSON file or create default if not exists"""
        default_config = {
            "thresholds": {
                "scan_detection": 10,  # Number of distinct ports in a time window
                "time_window": 60,     # Time window in seconds
                "aggressive_scan": 20  # Threshold for aggressive scan detection
            },
            "firewall": {
                "default_policy": "DROP",
                "allowed_ports": [80, 443, 22],  # Default allowed ports
                "block_duration": 3600  # Block duration in seconds
            },
            "port_knocking": {
                "enabled": True,
                "sequence": [5678, 7856, 6587],
                "timeout": 30,  # Seconds to complete the sequence
                "protected_port": 22
            },
            "honeypots": {
                "ports": [21, 23, 445, 3306, 5432],
                "response_delay": 2
            },
            "tarpitting": {
                "enabled": True,
                "delay": 10,  # Seconds to delay response
                "ports": [22, 23, 25]
            },
            "rate_limiting": {
                "max_connections": 15,
                "time_period": 60,  # Seconds
                "penalty_time": 300  # Block for this many seconds
            },
            "fail2ban": {
                "enabled": True,
                "known_scanners": ["nmap", "zenmap", "angry_ip_scanner", "masscan"],
                "ban_time": 3600
            },
            "email": {
                "smtp_server": "guntakamaheshwarreddy9@gmail.com",
                "smtp_port": 587,
                "use_tls": True,
                "username": "guntakamaheshwarreddy9@gmail.com",  # To be provided separately for security
                "password": "mahi@2468",  # To be provided separately for security
                "from_address": "Mahi"
            }
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
                    logger.info(f"Loaded configuration from {self.config_file}")
            else:
                self.config = default_config
                with open(self.config_file, 'w') as f:
                    json.dump(default_config, f, indent=4)
                logger.info(f"Created default configuration at {self.config_file}")
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            self.config = default_config
    
    def initialize_firewall(self):
        """Initialize the firewall with default rules"""
        logger.info("Initializing firewall")
        
        # Check if iptables is available
        try:
            subprocess.run(["which", "iptables"], check=True, stdout=subprocess.PIPE)
        except subprocess.CalledProcessError:
            logger.error("iptables not found, firewall initialization failed")
            return
        
        # Flush existing rules
        subprocess.run(["iptables", "-F"], check=True)
        
        # Set default policies
        default_policy = self.config["firewall"]["default_policy"]
        subprocess.run(["iptables", "-P", "INPUT", default_policy], check=True)
        
        # Allow loopback
        subprocess.run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=True)
        
        # Allow established connections
        subprocess.run([
            "iptables", "-A", "INPUT", "-m", "conntrack", 
            "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"
        ], check=True)
        
        # Allow specified ports
        for port in self.config["firewall"]["allowed_ports"]:
            subprocess.run([
                "iptables", "-A", "INPUT", "-p", "tcp", 
                "--dport", str(port), "-j", "ACCEPT"
            ], check=True)
        
        logger.info("Firewall initialized successfully")
    
    def block_ip(self, ip, duration=None):
        """Block an IP address using iptables"""
        if not duration:
            duration = self.config["firewall"]["block_duration"]
            
        if ip in self.blocked_ips:
            logger.info(f"IP {ip} is already blocked")
            return
            
        try:
            subprocess.run([
                "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"
            ], check=True)
            
            self.blocked_ips.add(ip)
            logger.info(f"Blocked IP: {ip} for {duration} seconds")
            
            # Send email notification
            self.send_alert_email(f"IP Blocked: {ip}", 
                                 f"Blocked IP {ip} for {duration} seconds due to port scanning activity.")
            
            # Schedule unblock
            threading.Timer(duration, self.unblock_ip, args=[ip]).start()
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block IP {ip}: {e}")
    
    def unblock_ip(self, ip):
        """Unblock an IP address"""
        try:
            subprocess.run([
                "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"
            ], check=True)
            
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
                
            logger.info(f"Unblocked IP: {ip}")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
    
    def setup_honeypots(self):
        """Setup honeypot listeners on configured ports"""
        logger.info("Setting up honeypots")
        
        for port in self.config["honeypots"]["ports"]:
            # Start honeypot listener in a separate thread
            threading.Thread(
                target=self.honeypot_listener,
                args=(port,),
                daemon=True
            ).start()
            logger.info(f"Honeypot set up on port {port}")
    
    def honeypot_listener(self, port):
        """Honeypot listener implementation"""
        import socket
        
        # Create socket
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind(('0.0.0.0', port))
            server.listen(5)
            logger.info(f"Honeypot listening on port {port}")
            
            while True:
                client, addr = server.accept()
                ip = addr[0]
                logger.warning(f"Honeypot triggered on port {port} by IP {ip}")
                
                # Record the hit
                self.honeypot_hits[ip] += 1
                
                # Send alert if multiple hits
                if self.honeypot_hits[ip] >= 3:
                    self.send_alert_email(
                        f"Honeypot Alert: {ip}",
                        f"IP {ip} has triggered honeypots {self.honeypot_hits[ip]} times. " +
                        f"Latest connection to honeypot on port {port}."
                    )
                    
                    # Block the IP
                    self.block_ip(ip)
                
                # Introduce a delay to simulate a real service
                time.sleep(self.config["honeypots"]["response_delay"])
                
                # Send fake banner
                fake_banners = {
                    21: "220 FTP Server Ready\r\n",
                    22: "SSH-2.0-OpenSSH_7.9\r\n",
                    23: "Welcome to Telnet Server\r\n",
                    25: "220 SMTP Server Ready\r\n",
                    80: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.6\r\n\r\n",
                    443: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.6\r\n\r\n",
                    445: "SMB Server\r\n",
                    3306: "5.7.22-MySQL\r\n",
                    5432: "PostgreSQL 12.3\r\n"
                }
                
                if port in fake_banners:
                    try:
                        client.send(fake_banners[port].encode())
                    except:
                        pass
                
                # Log the connection details
                try:
                    data = client.recv(1024)
                    if data:
                        logger.info(f"Honeypot data from {ip} on port {port}: {data}")
                except:
                    pass
                
                # Close the connection
                client.close()
                
        except Exception as e:
            logger.error(f"Error in honeypot on port {port}: {e}")
        finally:
            server.close()
    
    def configure_tarpitting(self):
        """Configure tarpitting for slow responses to suspicious IPs"""
        logger.info("Configuring tarpitting")
        
        if not self.config["tarpitting"]["enabled"]:
            logger.info("Tarpitting is disabled in configuration")
            return
            
        # Using iptables for tarpitting
        try:
            # First check if the required modules are available
            subprocess.run(["modprobe", "xt_TARPIT"], check=False)
            
            # Apply tarpit rules to configured ports
            for port in self.config["tarpitting"]["ports"]:
                subprocess.run([
                    "iptables", "-A", "INPUT", "-p", "tcp", "--dport", 
                    str(port), "-m", "state", "--state", "NEW", 
                    "-j", "TARPIT"
                ], check=False)
                
            logger.info("Tarpitting configured successfully")
        except Exception as e:
            logger.error(f"Failed to configure tarpitting: {e}")
            logger.info("Using fallback method for tarpitting via custom socket handling")
    
    def apply_tarpit(self, ip):
        """Apply tarpitting to a specific IP"""
        if ip in self.tarpit_ips:
            return
            
        self.tarpit_ips.add(ip)
        logger.info(f"Applied tarpitting to IP: {ip}")
        
        # Schedule removal
        threading.Timer(
            self.config["tarpitting"]["delay"] * 10,  # Keep in tarpit for 10x the delay time
            self.remove_from_tarpit,
            args=[ip]
        ).start()
    
    def remove_from_tarpit(self, ip):
        """Remove an IP from tarpitting"""
        if ip in self.tarpit_ips:
            self.tarpit_ips.remove(ip)
            logger.info(f"Removed tarpitting for IP: {ip}")
    
    def configure_rate_limiting(self):
        """Configure rate limiting using iptables"""
        logger.info("Configuring rate limiting")
        
        try:
            # Use iptables with limit module
            subprocess.run([
                "iptables", "-A", "INPUT", "-p", "tcp", "--syn",
                "-m", "limit", "--limit", "10/s", "--limit-burst", "20",
                "-j", "ACCEPT"
            ], check=False)
            
            subprocess.run([
                "iptables", "-A", "INPUT", "-p", "tcp", "--syn",
                "-j", "DROP"
            ], check=False)
            
            logger.info("Rate limiting configured successfully")
        except Exception as e:
            logger.error(f"Failed to configure rate limiting: {e}")
    
    def apply_rate_limit(self, ip):
        """Apply rate limiting to a specific IP"""
        if ip in self.rate_limited_ips:
            return
            
        self.rate_limited_ips.add(ip)
        
        try:
            # Add specific rate limiting rule for this IP
            subprocess.run([
                "iptables", "-A", "INPUT", "-s", ip, "-p", "tcp",
                "-m", "limit", "--limit", "3/minute", "--limit-burst", "5",
                "-j", "ACCEPT"
            ], check=True)
            
            subprocess.run([
                "iptables", "-A", "INPUT", "-s", ip, "-p", "tcp",
                "-j", "DROP"
            ], check=True)
            
            logger.info(f"Applied rate limiting to IP: {ip}")
            
            # Schedule removal
            threading.Timer(
                self.config["rate_limiting"]["penalty_time"],
                self.remove_rate_limit,
                args=[ip]
            ).start()
            
        except Exception as e:
            logger.error(f"Failed to apply rate limiting to {ip}: {e}")
    
    def remove_rate_limit(self, ip):
        """Remove rate limiting for an IP"""
        if ip not in self.rate_limited_ips:
            return
            
        try:
            # Remove specific rate limiting rules
            subprocess.run([
                "iptables", "-D", "INPUT", "-s", ip, "-p", "tcp",
                "-m", "limit", "--limit", "3/minute", "--limit-burst", "5",
                "-j", "ACCEPT"
            ], check=False)
            
            subprocess.run([
                "iptables", "-D", "INPUT", "-s", ip, "-p", "tcp",
                "-j", "DROP"
            ], check=False)
            
            self.rate_limited_ips.remove(ip)
            logger.info(f"Removed rate limiting for IP: {ip}")
            
        except Exception as e:
            logger.error(f"Failed to remove rate limiting from {ip}: {e}")
    
    def configure_fail2ban(self):
        """Configure Fail2Ban integration"""
        logger.info("Configuring Fail2Ban integration")
        
        if not self.config["fail2ban"]["enabled"]:
            logger.info("Fail2Ban integration is disabled in configuration")
            return
            
        try:
            # Check if fail2ban is installed
            subprocess.run(["which", "fail2ban-client"], check=True, stdout=subprocess.PIPE)
            
            # Create a custom fail2ban filter for port scanning
            filter_path = "/etc/fail2ban/filter.d/port-scan.conf"
            
            filter_content = """[Definition]
failregex = ^.*Port scan detected from <HOST>.*$
ignoreregex =
"""
            
            with open(filter_path, 'w') as f:
                f.write(filter_content)
                
            # Create a custom jail for port scanning
            jail_path = "/etc/fail2ban/jail.d/port-scan.conf"
            
            jail_content = f"""[port-scan]
enabled = true
filter = port-scan
logpath = {os.path.abspath("port_scan_detector.log")}
maxretry = 1
findtime = 3600
bantime = {self.config["fail2ban"]["ban_time"]}
action = iptables-allports[name=port-scan]
         mail[name=port-scan, dest={self.admin_email}, sender=fail2ban@localhost]
"""
            
            with open(jail_path, 'w') as f:
                f.write(jail_content)
                
            # Reload fail2ban
            subprocess.run(["fail2ban-client", "reload"], check=True)
            
            logger.info("Fail2Ban integration configured successfully")
            
        except subprocess.CalledProcessError:
            logger.error("Fail2Ban not found, integration skipped")
        except Exception as e:
            logger.error(f"Failed to configure Fail2Ban: {e}")
    
    def send_to_fail2ban(self, ip, reason):
        """Send an IP to fail2ban for blocking"""
        if not self.config["fail2ban"]["enabled"]:
            return
            
        logger.warning(f"Port scan detected from {ip}: {reason}")
        
        try:
            # The log message will be caught by fail2ban's filter
            with open("port_scan_detector.log", "a") as f:
                f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Port scan detected from {ip}: {reason}\n")
            
            logger.info(f"Sent IP {ip} to Fail2Ban")
            
        except Exception as e:
            logger.error(f"Failed to send IP to Fail2Ban: {e}")
    
    def send_alert_email(self, subject, message):
        """Send an email alert"""
        if not self.admin_email:
            logger.warning("Admin email not configured, skipping alert")
            return
            
        email_config = self.config["email"]
        
        if not email_config["username"] or not email_config["password"]:
            logger.warning("Email credentials not configured, skipping alert")
            return
            
        try:
            msg = MIMEMultipart()
            msg['From'] = email_config["from_address"] or email_config["username"]
            msg['To'] = self.admin_email
            msg['Subject'] = f"[Port Scan Detector] {subject}"
            
            body = f"""
Port Scan Detector Alert

{message}

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Hostname: {os.uname().nodename}
Interface: {self.interface}

This is an automated message from Port Scan Detector.
"""
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(email_config["smtp_server"], email_config["smtp_port"])
            
            if email_config["use_tls"]:
                server.starttls()
                
            server.login(email_config["username"], email_config["password"])
            text = msg.as_string()
            server.sendmail(msg['From'], msg['To'], text)
            server.quit()
            
            logger.info(f"Alert email sent: {subject}")
            
        except Exception as e:
            logger.error(f"Failed to send alert email: {e}")
    
    def process_port_knock(self, ip, port):
        """Process port knocking sequence"""
        if not self.config["port_knocking"]["enabled"]:
            return
            
        sequence = self.config["port_knocking"]["sequence"]
        protected_port = self.config["port_knocking"]["protected_port"]
        
        # Check if this is a port in our sequence
        if port not in sequence:
            # Reset the sequence for this IP if they hit a port not in sequence
            if ip 
