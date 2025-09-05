#!/usr/bin/python3
import json
import logging
import os
import subprocess
import sys

os.makedirs("./logs", exist_ok=True)

while logging.root.handlers:
    logging.root.removeHandler(logging.root.handlers[-1])

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler("./logs/custom-fail2ban.log"),
        logging.StreamHandler(sys.stdout),
    ],
)


def get_jail_by_signature_severity(signature_severity):
    logging.info(
        f"get_jail_by_signature_severity called with: " f"{signature_severity}"
    )
    severity_to_jail = {
        "Critical": "suricata-threats",
        "Major": "suricata-threats",
        # "Minor": "suricata-threats",
        # "Informational": "suricata-threats",
    }
    return severity_to_jail.get(signature_severity, "default-jail")


def fail2ban(ip_address, fail2ban_jail, action):
    """Send control message to check if IP is already being processed"""
    logging.debug(
        f"fail2ban() called with ip={ip_address}, "
        f"jail={fail2ban_jail}, action={action}"
    )
    if action == "add":
        command = ["sudo", "fail2ban-client", "set", fail2ban_jail, "banip", ip_address]
        action_text = "banned"
    else:  # delete
        command = [
            "sudo",
            "fail2ban-client",
            "set",
            fail2ban_jail,
            "unbanip",
            ip_address,
        ]
        action_text = "unbanned"
    try:
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        logging.info(
            f"Successfully {action_text} IP {ip_address} in jail "
            f"{fail2ban_jail}. Output: {result.stdout.strip()}"
        )
        return True

    except subprocess.CalledProcessError as e:
        logging.error(
            f"Failed to {action_text} IP {ip_address}. " f"Error: {e.stderr.strip()}"
        )
        return False


def send_control_message(srcip):
    """Read response from STDIN"""
    try:
        logging.debug(f"send_control_message() called with ip={srcip}")
        control_message = {
            "version": 1,
            "origin": {"name": "fail2ban", "module": "active-response"},
            "command": "check_keys",
            "parameters": {"keys": [srcip]},
        }
        logging.info(f"Sending control message for IP {srcip}")
        if sys.stdout.isatty():
            logging.info(
                f"Skipping control message for {srcip} " f"(running in terminal mode)"
            )
            return False
        print(json.dumps(control_message), flush=True)
    except BrokenPipeError:
        logging.warning(
            f"Broken pipe when sending control message for IP {srcip}, "
            "proceeding without control check"
        )
        return False


def read_response():
    logging.debug("read_response() called")
    try:
        response = input()
        logging.info("Received response from standard input")
        return json.loads(response)
    except EOFError:
        logging.info("No response received on stdin (EOF), proceeding")
        return None
    except json.JSONDecodeError as e:
        logging.warning(f"Failed to decode JSON response: {e}")
        return None


def main():
    try:
        alert_line = sys.stdin.readline()
        if not alert_line:
            logging.error("No JSON data received from stdin.")
            sys.exit(1)

        alert_json = json.loads(alert_line)
    except Exception as e:
        logging.error(f"Failed to parse JSON from stdin: {e}")
        sys.exit(1)

    params = alert_json.get("parameters", {})

    # extract IP
    src_ip = params.get("alert", {}).get("data", {}).get("srcip") or params.get(
        "alert", {}
    ).get("data", {}).get("src_ip")

    if not src_ip:
        logging.error("No source IP found in alert")
        sys.exit(1)

    # extract signature severity
    alert_data = params.get("alert", {}).get("data", {}).get("alert", {})
    signature_severity = alert_data.get("metadata", {}).get(
        "signature_severity", [None]
    )[0] or str(alert_data.get("severity", "N/A"))

    jail_name = get_jail_by_signature_severity(signature_severity)
    logging.info(f"Using jail: {jail_name} for severity: {signature_severity}")

    command = params.get("command", "add")

    if command == "add":
        send_control_message(src_ip)
        response = read_response()
        if response:
            if response.get("command") == "continue":
                fail2ban(src_ip, jail_name, "add")
            else:
                logging.info(f"Aborting action for {src_ip}")
        else:
            fail2ban(src_ip, jail_name, "add")

    elif command == "delete":
        fail2ban(src_ip, jail_name, "delete")


if __name__ == "__main__":
    main()
    logging.info("Successfully executed active response")
