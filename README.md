# NIDS
A basic NIDS without using SNORT or other tools, you can modify all parameters as per your pref...

How it works
--> Packet Monitoring: The script uses Scapy to continuously monitor network traffic, printing out a summary of each packet it captures.

--> Working Hours Check: It checks if traffic is happening outside normal working hours (6 AM to 9 PM). If traffic is detected during these hours, an alert is     
triggered and an email is sent.

--> Suspicious IP Detection: The script keeps track of IP addresses and assigns a "suspicion score" based on:

    Accessing uncommon ports (like 12345 or 54321).
    Sending too many packets (above a certain threshold).

--> Dynamic Behavior Detection: If an IP’s score exceeds the set limit, it's marked as suspicious, and the script generates an alert.

--> Email Alerts: After detecting unusual activity (like traffic outside working hours or suspicious behavior), the script waits for 1 minute before sending an email notification to a specified address.

--> Automated Alerts: The script uses Python's smtplib to send the email, letting you know when something suspicious is happening on your network.
