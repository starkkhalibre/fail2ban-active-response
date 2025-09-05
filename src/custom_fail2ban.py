#!/var/ossec/framework/python/bin/python3
import json 
import sys
import subprocess
import logging
import os

os.makedirs('./logs',exist_ok=True)

while logging.root.handlers:
    logging.root.removeHandler(logging.root.handlers[-1])

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler("./logs/custom-fail2ban.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

def get_jail_by_signature_severity(signature_severity):
    logging.info(f"get_jail_by_signature_severity called with: {signature_severity}")
    severity_to_jail = {
        "Critical": "critical-threats",
        "Major": "major-threats",
        "Minor": "minor-threats",
        "Informational": "informational-threats"
    }
    return severity_to_jail.get(signature_severity, "default-jail")

def fail2ban(ip_address, fail2ban_jail, action):
    """Send control message to check if IP is already being processed"""
    logging.debug(f"fail2ban() called with ip={ip_address}, jail={fail2ban_jail}, action={action}")
    if action == "add":
        command = ["sudo", "fail2ban-client", "set", fail2ban_jail, "banip", ip_address]
        action_text = "banned"
    else:  # delete
        command = ["sudo", "fail2ban-client", "set", fail2ban_jail, "unbanip", ip_address]
        action_text = "unbanned"
    try:
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logging.info(f"Successfully {action_text} IP {ip_address} in jail {fail2ban_jail}. Output: {result.stdout.strip()}")
        return True
    
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to {action_text} IP {ip_address}. Error: {e.stderr.strip()}")
        return False

def send_control_message(srcip):
    """Read response from STDIN"""
    try:
        logging.debug(f"send_control_message() called with ip={srcip}")
        contronl_message = {
            "version": 1,
            "origin": {
                "name": "custom-fail2ban",
                "module": "active-response"
            },
            "command": "check_keys",
            "parameters": {
                "keys": [srcip]
            }
        }
        logging.info(f"Sending control message for IP {srcip}")
        print(json.dumps(contronl_message), flush=True)
    
    except Exception as e:
        logging.error(f"Error sending control message: {e}")

def read_response():
    logging.debug("read_response() called")
    try:
        response = input()
        logging.info("Received response from standard input")
        return json.loads(response)
    except (json.JSONDecodeError, EOFError) as e:
        logging.warning(f"Failed to read or decode response: {e}")
        return None

def main(): 
    logging.debug(" main() started")
    if len(sys.argv) < 2:
        sys.exit(1)
    try:
        with open (sys.argv[1]) as alert_file:
            alert_json = json.load(alert_file)
    except (FileNotFoundError, json.JSONDecodeError):
        sys.exit(1)
    
    source_data = alert_json.get('parameters', alert_json)
    src_ip = source_data.get('alert', {}).get('data',{}).get('srcip', 'N/A')
    signature_severity = source_data.get('alert',{}).get('data', {}).get('alert', {}).get('metadata', {}).get('signature_severity', ['N/A'])[0]

    command = alert_json.get('command','add')

    if src_ip == 'N/A':
        logging.error("No source IP found in alert")
        sys.exit(1)
    
    jail_name = get_jail_by_signature_severity(signature_severity)
    
    if command == 'add':
        send_control_message(src_ip)
        response = read_response()

        if response:
            response_command = response.get('command','continue')

            if response_command == 'continue':
                fail2ban(src_ip,jail_name,'add')

            elif response_command == 'aborted':
                logging.info(f'Aborting action, {src_ip} is already in process')
                sys.exit(0)

        else:
            fail2ban(src_ip,jail_name,'add')

    elif command == 'delete':
        fail2ban(src_ip,jail_name,'delete')
        
if __name__ == "__main__":
    main()
    logging.info('Successfully executed active response')