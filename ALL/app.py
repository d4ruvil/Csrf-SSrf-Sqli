from flask import Flask, render_template, request, redirect, url_for, flash
import subprocess
import re
import logging

app = Flask(__name__)
app.secret_key = 'your_secret_key'

logging.basicConfig(level=logging.DEBUG)

def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        tool = request.form['tool']
        
        logging.debug(f"Selected tool: {tool}")

        if tool != '3':  # XXE tool does not require the main URL
            url = request.form['url']
            if not is_valid_url(url):
                flash('Invalid URL. Please enter a valid URL.', 'danger')
                return redirect(url_for('index'))

        output = ""
        try:
            if tool == '1':
                result = subprocess.run(['python', 'csrf.py', url], capture_output=True, text=True)
                output = f"<h2>CSRF Detection Results:</h2><pre>{result.stdout}</pre>"
            elif tool == '2':
                result = subprocess.run(['python', 'ssrf.py', url], capture_output=True, text=True)
                output = f"<h2>SSRF Detection Results:</h2><pre>{result.stdout}</pre>"
            elif tool == '3':
                choice = request.form['XXE_choice']
                lab_url = request.form['lab_url']
                if choice == '1':
                    login_url = request.form['login_url']
                    username = request.form['username']
                    password = request.form['password']
                    result = subprocess.run(
                        ['python', 'XXE.py', choice, lab_url, '--login-url', login_url, '--username', username, '--password', password],
                        capture_output=True, text=True
                    )
                elif choice == '2':
                    session_cookie = request.form['session_cookie']
                    result = subprocess.run(
                        ['python', 'XXE.py', choice, lab_url, '--session-cookie', session_cookie],
                        capture_output=True, text=True
                    )
                output = f"<h2>XXE Detection Results:</h2><pre>{result.stdout}</pre>"
            elif tool == '4':
                par = request.form['par']
                method = request.form['method'].upper()
                result = subprocess.run(['python', 'sqli.py', url, par, method], capture_output=True, text=True)
                output = f"<h2>SQL Injection Detection Results:</h2><pre>{result.stdout}</pre>"
            elif tool == '5':
                # Run CSRF, SSRF, and SQLi
                par = request.form['par']
                method = request.form['method'].upper()
                result1 = subprocess.run(['python', 'csrf.py', url], capture_output=True, text=True)
                result2 = subprocess.run(['python', 'ssrf.py', url], capture_output=True, text=True)
                result4 = subprocess.run(['python', 'sqli.py', url, par, method], capture_output=True, text=True)
                output = (
                    f"<h2>CSRF Detection Results:</h2><pre>{result1.stdout}</pre>"
                    f"<h2>SSRF Detection Results:</h2><pre>{result2.stdout}</pre>"
                    f"<h2>SQL Injection Detection Results:</h2><pre>{result4.stdout}</pre>"
                )

                # Optionally run XXE if provided
                if 'run_XXE' in request.form:
                    choice = request.form['XXE_choice']
                    lab_url = request.form['lab_url']
                    if choice == '1':
                        login_url = request.form['login_url']
                        username = request.form['username']
                        password = request.form['password']
                        result3 = subprocess.run(
                            ['python', 'XXE.py', choice, lab_url, '--login-url', login_url, '--username', username, '--password', password],
                            capture_output=True, text=True
                        )
                    elif choice == '2':
                        session_cookie = request.form['session_cookie']
                        result3 = subprocess.run(
                            ['python', 'XXE.py', choice, lab_url, '--session-cookie', session_cookie],
                            capture_output=True, text=True
                        )
                    output += f"<h2>XXE Detection Results:</h2><pre>{result3.stdout}</pre>"
            else:
                flash('Invalid choice. Please select a valid tool.', 'danger')
                return redirect(url_for('index'))
        except Exception as e:
            logging.error(f"Error running tool: {e}")
            output = f"<h2>Error</h2><pre>{str(e)}</pre>"

        return render_template('result.html', output=output)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
