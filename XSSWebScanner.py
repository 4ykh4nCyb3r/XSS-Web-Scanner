import requests
import urllib.parse
from bs4 import BeautifulSoup
from collections import deque

class WebScanner:
    def __init__(self, base_url, skip_links):
        self.http_session = requests.Session()
        self.base_url = base_url
        self.discovered_links = set()
        self.links_to_skip = set(skip_links)

    def fetch_links(self, url):
        """Fetch links from a given URL using BeautifulSoup."""
        try:
            response = self.http_session.get(url, timeout=5)
            response.raise_for_status()  # Raise an error for HTTP failures (4xx, 5xx)
        except requests.RequestException:
            return []  # Return empty if there's a network issue

        soup = BeautifulSoup(response.text, "html.parser")
        links = []

        for a_tag in soup.find_all("a", href=True):
            full_link = urllib.parse.urljoin(url, a_tag["href"])  # Convert to absolute URL

            # Remove fragments (#section) for uniqueness
            full_link = full_link.split("#")[0]

            if full_link.startswith(self.base_url) and full_link not in self.discovered_links:
                links.append(full_link)

        return links

    def start_crawling(self):
        """Breadth-First Search (BFS) to avoid infinite recursion."""
        queue = deque([self.base_url])

        while queue:
            url = queue.popleft()

            if url in self.links_to_skip or url in self.discovered_links:
                continue

            self.discovered_links.add(url)
            print("[+] Discovered URL:", url)

            new_links = self.fetch_links(url)
            queue.extend(new_links)  # Add new links to the queue

    def get_forms(self, url):
        """Extract all forms from a given webpage."""
        try:
            response = self.http_session.get(url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            return soup.find_all("form")
        except requests.RequestException:
            return []

    def submit_form(self, form, payload, url):
        """Submit a form with the given payload to check for vulnerabilities."""
        action_url = form.get("action")
        full_url = urllib.parse.urljoin(url, action_url or url)
        method = form.get("method", "get").lower()

        form_data = {}
        for field in form.find_all("input"):
            field_name = field.get("name")
            field_value = field.get("value", "")

            if field_name:  # Ensure it's a valid input field
                form_data[field_name] = payload if field.get("type") == "text" else field_value

        try:
            if method == "post":
                return self.http_session.post(full_url, data=form_data, timeout=5)
            return self.http_session.get(full_url, params=form_data, timeout=5)
        except requests.RequestException:
            return None

    def execute_scan(self):
        """Perform XSS testing on discovered links and forms."""
        for link in self.discovered_links:
            forms = self.get_forms(link)

            for form in forms:
                print("[+] Testing form on", link)
                if self.check_xss_in_form(form, link):
                    print("\n[!!!] XSS found in form on:", link)
                    print(form, "\n")

            if "=" in link:
                print("[+] Testing URL:", link)
                if self.check_xss_in_link(link):
                    print("\n[!!!] XSS found in URL:", link, "\n")

    def check_xss_in_form(self, form, url):
        """Check for XSS vulnerabilities in form submissions."""
        xss_payload = "<script>alert('XSS')</script>"
        response = self.submit_form(form, xss_payload, url)

        return response is not None and xss_payload in response.text

    def check_xss_in_link(self, url):
        """Check for XSS vulnerabilities in URL parameters."""
        xss_payload = "<script>alert('XSS')</script>"
        if "?" not in url:
            return False  # No parameters to inject

        # Inject payload into URL parameter values
        injected_url = url.replace("=", "=" + urllib.parse.quote(xss_payload))

        try:
            response = self.http_session.get(injected_url, timeout=5)
            return xss_payload in response.text
        except requests.RequestException:
            return False


# Configuration
scan_target_url = "https://example.com"  # Replace with your target URL
ignore_list = ["https://example.com/logout"]  # Example: URLs to avoid

# Initialize and run the scanner
xss_scanner = WebScanner(scan_target_url, ignore_list)
xss_scanner.start_crawling()
xss_scanner.execute_scan()
