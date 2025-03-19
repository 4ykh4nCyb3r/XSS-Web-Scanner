WebScanner is a simple web crawler and **Cross-Site Scripting (XSS) vulnerability scanner** written in Python. It scans a target website for **forms** and **URL parameters**, then attempts to inject a basic **XSS payload** (`<script>alert('XSS')</script>`) to check for vulnerabilities.

## Features
✅ **Crawls a website** recursively, discovering internal links.  
✅ **Extracts all forms** from each page and submits test payloads.  
✅ **Tests URL parameters** for potential XSS vulnerabilities.  
✅ **Handles both GET and POST requests** dynamically.  
✅ **Skips specified links** (e.g., logout pages to avoid logging out).  
✅ **Prevents infinite loops** using a queue-based crawling mechanism.  
✅ **Avoids unnecessary re-scanning of the same URLs**.  

---

## Installation

### **1. Install Python 3**
Ensure you have **Python 3** installed. You can check with:

python --version


### **2. Install Dependencies**
Run the following command to install required modules:

pip install requests beautifulsoup4


---

## Usage

### **1. Set Target URL**
Modify the script and set the target website:

```python
scan_target_url = "https://example.com"  # Replace with your target URL
ignore_list = ["https://example.com/logout"]  # Example: URLs to avoid

 Run the Scanner
Execute the script in your terminal:

python webscanner.py

3. Understanding the Output

[+] Discovered URL: URL found during crawling

[+] Testing form on: Testing a detected form for XSS

[!!!] XSS found in form on: Possible XSS vulnerability detected in a form

[+] Testing URL: Testing a URL parameter for XSS

[!!!] XSS found in URL: Possible XSS vulnerability detected in a URL

Example Output

[+] Discovered URL: https://example.com/home
[+] Discovered URL: https://example.com/search?q=test
[+] Testing form on https://example.com/contact
[!!!] XSS found in form on: https://example.com/contact
Code Overview
The script follows these steps:

Crawls the website, finding internal links.

Extracts and analyzes forms, injecting an XSS payload.

Modifies URL parameters to test for XSS vulnerabilities.

Reports vulnerabilities where the injected script appears in responses.

Limitations

Does not detect all XSS vulnerabilities (e.g., advanced JavaScript-based XSS).

Works best on public websites (avoid scanning unauthorized sites).

Some websites block automated scripts, causing errors.

Legal Disclaimer
🚨 This tool is for educational and security research purposes only.
Do not use it on unauthorized websites without permission.
The author is not responsible for any misuse of this tool.

Possible future Improvements
🔹 Support for more payloads (Reflected & Stored XSS).
🔹 Integration with Selenium for real browser-based testing.
🔹 Better error handling for dynamic forms.