import requests
import urllib.parse
from bs4 import BeautifulSoup
from collections import deque
import sys
from tqdm import tqdm

class WebScanner:
    def __init__(self, base_url, skip_links):
        self.http_session = requests.Session()
        self.base_url = base_url.rstrip('/')  # normalize URL
        self.discovered_links = set()
        self.links_to_skip = set(skip_links)
        self.debug = False  # set to True for detailed logs

    def fetch_links(self, url):
        """Fetch all links from a given URL using BeautifulSoup."""
        try:
            response = self.http_session.get(url, timeout=5)
            response.raise_for_status()
        except requests.RequestException:
            if self.debug:
                tqdm.write(f"[-] Failed to fetch {url}")
            return []

        soup = BeautifulSoup(response.text, "html.parser")
        links = []

        for a_tag in soup.find_all("a", href=True):
            full_link = urllib.parse.urljoin(url, a_tag["href"])
            full_link = full_link.split("#")[0].rstrip('/')  # remove fragments and trailing slash

            if full_link.startswith(self.base_url) and full_link not in self.discovered_links:
                links.append(full_link)

        if self.debug:
            tqdm.write(f"[DEBUG] Found {len(links)} links on {url}")
        return links

    def start_crawling(self, max_depth=2):
        """Crawl website breadth-first up to max_depth levels."""
        queue = deque([(self.base_url, 0)])  # (url, depth)

        with tqdm(desc=f"Crawling (max depth={max_depth})", unit="link") as crawl_bar:
            while queue:
                url, depth = queue.popleft()

                # Skip if already visited or ignored
                if url in self.links_to_skip or url in self.discovered_links:
                    continue

                self.discovered_links.add(url)
                crawl_bar.update(1)

                if self.debug:
                    tqdm.write(f"[Crawling] {url} (depth={depth})")

                # Stop if we've reached max depth
                if depth >= max_depth:
                    continue

                new_links = self.fetch_links(url)
                for nl in new_links:
                    if nl not in self.discovered_links and nl not in self.links_to_skip:
                        queue.append((nl, depth + 1))

    def get_forms(self, url):
        """Extract all forms from a given webpage."""
        try:
            response = self.http_session.get(url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            return soup.find_all("form")
        except requests.RequestException:
            return []

    def submit_form(self, form, payload, url):
        """Submit a form with a given payload."""
        action_url = form.get("action")
        full_url = urllib.parse.urljoin(url, action_url or url)
        method = form.get("method", "get").lower()

        form_data = {}
        for field in form.find_all("input"):
            name = field.get("name")
            value = field.get("value", "")
            if name:
                form_data[name] = payload if field.get("type", "").lower() == "text" else value

        try:
            if method == "post":
                return self.http_session.post(full_url, data=form_data, timeout=5)
            return self.http_session.get(full_url, params=form_data, timeout=5)
        except requests.RequestException:
            return None

    def execute_scan(self):
        """Perform XSS testing on all discovered links and forms."""
        links_list = list(self.discovered_links)
        with tqdm(total=len(links_list), desc="Scanning links", unit="link") as scan_bar:
            for link in links_list:
                forms = self.get_forms(link)

                for form in forms:
                    tqdm.write(f"[+] Testing form on {link}")
                    if self.check_xss_in_form(form, link):
                        tqdm.write(f"\n[!!!] XSS found in form on: {link}\n")
                        tqdm.write(str(form))

                if "=" in link:
                    tqdm.write(f"[+] Testing URL: {link}")
                    if self.check_xss_in_link(link):
                        tqdm.write(f"\n[!!!] XSS found in URL: {link}\n")

                scan_bar.update(1)

    def check_xss_in_form(self, form, url):
        """Check if a form is vulnerable to XSS."""
        xss_payload = "<script>alert('XSS')</script>"
        response = self.submit_form(form, xss_payload, url)
        return response is not None and xss_payload in response.text

    def check_xss_in_link(self, url):
        """Check if URL parameters are vulnerable to XSS."""
        xss_payload = "<script>alert('XSS')</script>"
        if "?" not in url:
            return False
        injected_url = url.replace("=", "=" + urllib.parse.quote(xss_payload))
        try:
            response = self.http_session.get(injected_url, timeout=5)
            return xss_payload in response.text
        except requests.RequestException:
            return False


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <target_url> <ignore_file>")
        sys.exit(1)

    scan_target_url = sys.argv[1]
    ignore_file = sys.argv[2]

    try:
        with open(ignore_file, "r") as f:
            ignore_list = [line.strip().rstrip('/') for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Ignore file '{ignore_file}' not found. Proceeding without ignore list.")
        ignore_list = []

    try:
        xss_scanner = WebScanner(scan_target_url, ignore_list)
        xss_scanner.start_crawling(max_depth=2)  # <-- crawl up to 2 levels
        xss_scanner.execute_scan()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting...")
