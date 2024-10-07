# WebSentry
WebSentry is a robust web technology and security analysis tool, designed to give you deep insights into the technologies powering your web applications and identify potential security gaps. Whether you're assessing server configurations or checking for missing security headers, WebSentry helps ensure your web infrastructure is both efficient and secure.

# Key Features:
1. Technology Detection: Identify all technologies running behind the web server, including CMS, frameworks, and libraries using BuiltWith and WhatWeb.
2. Security Header Analysis: Detect missing or misconfigured HTTP security headers such as Content-Security-Policy, X-Frame-Options, and more.
3. HTTP Method Discovery: Check which HTTP methods (e.g., GET, POST, PUT, DELETE) are allowed by the server for better security posture.
4. Firewall Detection: Analyze and detect firewall technologies used to protect the web application.

WebSentry provides a thorough breakdown of web application technology stacks while highlighting areas for security improvements, helping you better understand your web infrastructure.

# Attributes
1) BuiltWith Detection (-b): Identify the technologies used by a web server via the BuiltWith API.
2) WhatWeb Detection (-w): Use WhatWeb to discover technologies and plugins used on the target website.
3) Missing Security Headers Check (-m): Verify if critical HTTP security headers are missing.
4) Allowed HTTP Methods Detection (-a): Detect HTTP methods allowed by the server (e.g., GET, POST, PUT, DELETE).
5) Firewall Detection (-f): Check the HTTP headers for known firewall technologies (e.g., Cloudflare, AWS WAF).
6) Run All Features (-A): Execute all scanning features in one go.

# Usage
Basic Syntax:
bash
Copy code
python scanner.py -u <target URL> [options]

# Options:
Flag	Description
-u	Target URL (Required). Example: http://example.com
-b	Use BuiltWith for technology detection.
-w	Use WhatWeb for technology detection.
-m	Check for missing security headers.
-a	Check allowed HTTP methods.
-f	Detect firewall technologies.
-A	Run all the above features in one command.
Example Usage:
Run all features on a website:

bash
Copy code
python scanner.py -u http://example.com -A
Run individual checks:

To detect technologies using BuiltWith:
bash
Copy code
python scanner.py -u http://example.com -b
To check for missing security headers:
bash
Copy code
python scanner.py -u http://example.com -m
Sample Output
The output is neatly formatted in boxes for each feature, displaying relevant data like allowed HTTP methods, missing security headers, technologies detected, and firewalls found.

Example output:

markdown
Copy code
============================ Technologies Detected by BuiltWith ============================
Technology                       | Details
=============================================================================================
Python                           | Django
Bootstrap                        | v4.3.1
=============================================================================================

============================ Missing Security Headers ============================
Header                                        | Status
=============================================================================================
X-Content-Type-Options                        | is present.
Content-Security-Policy                       | is missing.
Strict-Transport-Security                     | is missing.
=============================================================================================
Installation
To install the required dependencies, follow these steps:

Clone the repository:

bash
Copy code
git clone https://github.com/yourusername/web-vuln-scanner.git
cd web-vuln-scanner
Install the dependencies using pip:

bash
Copy code
pip install -r requirements.txt
Requirements
This tool is written in Python 3. Ensure you have Python installed, along with the following packages listed in requirements.txt.

To install dependencies:

bash
Copy code
pip install -r requirements.txt
Dependencies
requests: For making HTTP requests.
colorama: For colorizing terminal output.
builtwith: To detect technologies via the BuiltWith API.
subprocess: To run WhatWeb for technology detection.
argparse: For handling command-line arguments.
Contributions
Feel free to contribute by forking this repository and submitting a pull request. Any feature enhancements, bug fixes, or optimizations are welcome.
