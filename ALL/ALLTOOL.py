import subprocess
import re

def is_valid_url(url):
    # Regular expression for validating a URL
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
        r'localhost|' # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|' # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)' # ...or ipv6
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def main():
    # Loop until a valid URL is entered
    while True:
        url = input("ENTER URL: ")
        
        if is_valid_url(url):
            break
        else:
            print("Invalid URL format. Please enter a valid URL.")

    print("Select a tool to run:")
    print("1. CSRF Detection")
    print("2. SSRF Detection")
    print("3. XXE Detection")
    print("4. SQLI")
    print("5. Run All")

    choice = input("Enter your choice (1, 2, 3, 4, or 5): ")

    if choice == '1':
        subprocess.run(['python', 'CSRF.py', url])
    elif choice == '2':
        subprocess.run(['python', 'SSRF.py', url])
    elif choice == '3':
        print("XXE tool  ")
    elif choice == '4':
        subprocess.run(['python', 'SQLI.py', url])
    elif choice == '5':
        par = input("Enter the parameter to test(For SQLI): ")
        method = input("Enter the request method (GET/POST)(FOR SQLI): ").upper()
        subprocess.run(['python', 'CSRF.py', url])
        subprocess.run(['python', 'SSRF.py', url])
        #subprocess.run(['python', 'XXE.py', url])
        subprocess.run(['python', 'SQLI.py', url,par,method])
    else:
        print("Invalid choice. Please select 1, 2, 3, 4, or 5.")

if __name__ == "__main__":
    main()
