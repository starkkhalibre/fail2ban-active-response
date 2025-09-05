# 🛡️ Stateful Active Response for Wazuh

This repository provides an example of a **stateful active response** script for [Wazuh](https://wazuh.com/).  
A stateful active response executes an action when an alert is triggered and automatically **reverts** the action after a timeout.

For example:  
- Ban an IP address when brute-force is detected.  
- Unban the IP after 10 minutes.  

---

## 📖 What is a Stateful Active Response?

In Wazuh, active responses are scripts that automatically run when alerts meet certain conditions.

- **Stateless active response** → runs once, no cleanup.  
- **Stateful active response** → runs twice:  
  - First with `add` (apply the action).  
  - Later with `delete` (revert the action).  

This makes it ideal for temporary blocking, banning, or disabling resources.

---

## 🔄 How It Works

1. **Wazuh sends alert data** to the script on **STDIN** in JSON format.  

2. **Script parses JSON**:  
   - `command: "add"` → perform the main action (e.g., block IP).  
   - `command: "delete"` → revert the action (e.g., unblock IP).  

3. **Extract the key values** from the alert (for example, the attacker IP).  

4. **Send control message** back to Wazuh with the key(s):  

   ```json
   {
     "version": 1,
     "origin": {
       "name": "my-active-response",
       "module": "active-response"
     },
     "command": "check_keys",
     "parameters": {
       "keys": ["10.0.0.1"]
     }
   }

---

## 🔄 Control Message Flow

### 1. Write to STDOUT
After building the control message, the script writes it to **STDOUT** so Wazuh can process it.

---

### 2. Wait for Response via STDIN
The script then waits for a response message from **Wazuh Execd** through **STDIN**.

---

### 3. Parse the Response JSON
The response received from Wazuh will look like this:

```json
{
  "version": 1,
  "origin": {
    "name": "node01",
    "module": "wazuh-execd"
  },
  "command": "continue",
  "parameters": {}
}
```
---

### Test execution 

```python
python3 test/test.py
```

---