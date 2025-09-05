import sys
import os
import json
import logging

# Add src folder to Python path
sys.path.insert(0, os.path.abspath("./src"))

from custom_fail2ban import send_control_message, read_response, get_jail_by_signature_severity, fail2ban

# --- Setup logging for the test ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# --- Load test alert JSON ---
alert_file = os.path.abspath("./json/wazuh-active-response.json")
with open(alert_file) as f:
    alert_json = json.load(f)

source_data = alert_json.get('parameters', alert_json)
src_ip = source_data.get('alert', {}).get('data', {}).get('srcip', 'N/A')
signature_severity = source_data.get('alert', {}).get('data', {}).get('alert', {}).get('metadata', {}).get('signature_severity', ['N/A'])[0]

# --- Simulate command ---
command = alert_json.get('command', 'add')

if src_ip == 'N/A':
    logging.error("No source IP found in alert")
    sys.exit(1)

jail_name = get_jail_by_signature_severity(signature_severity)

# --- Simulate Wazuh response ---
def simulated_wazuh_response(ip):
    send_control_message(ip)  # prints JSON like Wazuh
    # instead of reading stdin, simulate a response dict
    response = {"command": "continue"}  # Wazuh would send this JSON
    logging.info(f"Simulated Wazuh response for IP {ip}: {response}")
    return response

# --- End-to-end test logic ---
if command == 'add':
    response = simulated_wazuh_response(src_ip)
    response_command = response.get('command', 'continue')

    if response_command == 'continue':
        # Call fail2ban; just logs since Fail2Ban is not installed
        logging.info(f"Would call fail2ban to add IP {src_ip} to jail {jail_name}")
        # To actually call fail2ban, uncomment the line below if Fail2Ban installed
        # fail2ban(src_ip, jail_name, 'add')
    elif response_command == 'aborted':
        logging.info(f'Aborting action, {src_ip} is already in process')

elif command == 'delete':
    logging.info(f"Would call fail2ban to remove IP {src_ip} from jail {jail_name}")
    # fail2ban(src_ip, jail_name, 'delete')

logging.info("End-to-end test finished")
