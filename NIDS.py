import smtplib #email
from scapy.all import * #sniffer
from datetime import datetime 
import time

WORKING_HOURS = (6, 21)  # 6 AM to 9 PM, feel free to edit out
THRESHOLD_PACKET_RATE = 1000  # Threshold for packet rate
UNCOMMON_PORTS = [12345, 54321]  # Add more ports as needed
SUSPICIOUS_IPS = {}  # Dictionary to track IP and suspicious score

# Email configuration
SENDER_EMAIL = 'your_email@example.com'
RECEIVER_EMAIL = 'receiver_email@example.com'
SMTP_SERVER = 'smtp.example.com'	#SMTP is used for email , port 587 specifically..
SMTP_PORT = 587
SMTP_PASSWORD = 'your_password'

# Function to send an email alert
def send_email_alert(ip):
    subject = (f"Security Alert: Suspicious Activity Detected from {ip}")
    body = (f"Suspicious activity has been detected from IP address {ip}. Immediate action may be required.")
    email_message = f"Subject: {subject}\n\n{body}"
    
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  
            server.login(SENDER_EMAIL, SMTP_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, email_message)
        print(f"Email alert sent to {RECEIVER_EMAIL} for IP: {ip}")
    except Exception as e:
        print(f"Failed to send email alert: {e}")

# Function to check if current time is within working hours
def check_working_hours():
    current_hour = datetime.now().hour
    return WORKING_HOURS[0] <= current_hour < WORKING_HOURS[1]


def detect_suspicious_behavior(ip, dst_port):
    # check for uncommon ports
    if dst_port in UNCOMMON_PORTS:
        SUSPICIOUS_IPS[ip] = SUSPICIOUS_IPS.get(ip, 0) + 10
    else:
        SUSPICIOUS_IPS[ip] = SUSPICIOUS_IPS.get(ip, 0) + 1

    # Consider an IP malicious if the suspicion score exceeds a threshold
    if SUSPICIOUS_IPS[ip] > THRESHOLD_PACKET_RATE:
        print(f"Alert! IP {ip} marked as suspicious due to unusual activity.")
        return True
    return False

def packet_callback(packet):
    print(packet.summary())  # Original packet monitoring
    
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_port = packet.getlayer(TCP).dport if packet.haslayer(TCP) else None
        
        #  Detect traffic outside working hours
        if not check_working_hours():
            print(f"Alert! Traffic detected outside working hours: {src_ip}")
            time.sleep(60)  # Wait for 1 minute
            send_email_alert(src_ip)  # Send email after 1 minute

        # Rule: Detect suspicious behavior dynamically
        if detect_suspicious_behavior(src_ip, dst_port):
            print(f"Alert! Detected suspicious behavior from IP: {src_ip}")
            time.sleep(60)  # Wait for 1 minute
            send_email_alert(src_ip)  # Send email after 1 minute

# Start sniffing packets with dynamic detection
print("Starting scanner")
sniff(prn=packet_callback, count=0)
