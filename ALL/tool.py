from tools.csrf import csrf_test
from tools.sqli import sqli_test
from tools.ssrf import ssrf_test
from tools.xxe import xxe_test

def run_tool(url, tool_choice):
    if tool_choice == 'csrf':
        return csrf_test(url)
    elif tool_choice == 'sqli':
        return sqli_test(url)
    elif tool_choice == 'ssrf':
        return ssrf_test(url)
    elif tool_choice == 'xxe':
        return xxe_test(url)
    else:
        return "Invalid tool choice."

# Example tool function stubs (replace with actual implementations)
def csrf_test(url):
    # Call your CSRF tool here
    return "CSRF test output"

def sqli_test(url):
    # Call your SQLi tool here
    return "SQL Injection test output"

def ssrf_test(url):
    # Call your SSRF tool here
    return "SSRF test output"

def xxe_test(url):
    # Call your XXE tool here
    return "XXE test output"
