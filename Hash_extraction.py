import requests
import re
import sys

# Regular expression to match hash-like strings (e.g., MD5, SHA-1, SHA-256)
hash_patterns = {
    "MD5": r'\b[a-fA-F0-9]{32}\b',
    "SHA-1": r'\b[a-fA-F0-9]{40}\b',
    "SHA-256": r'\b[a-fA-F0-9]{64}\b'
}

def scan_for_hashes(content):
    found_hashes = {}
    
    for hash_type, pattern in hash_patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            found_hashes[hash_type] = matches
    
    return found_hashes

def get_web_page_content(url):
    try:
        response = requests.get(url, verify=False)
        if response.status_code == 200:
            return response.text
        else:
            print(f"Failed to retrieve the page. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching the page: {e}")
    return None

def main():
    # Check if the URL is provided as a command-line argument
    if len(sys.argv) != 2:
        print("Usage: python o.py <URL>")
        sys.exit(1)
    
    url = sys.argv[1]
    print(f"Scanning URL: {url}")
    
    # Get the web page content
    page_content = get_web_page_content(url)
    
    if page_content:
        # Search for hash-like strings
        hashes = scan_for_hashes(page_content)
        
        if hashes:
            print("Hashes found:")
            for hash_type, hash_list in hashes.items():
                print(f"\n{hash_type} hashes:")
                for h in hash_list:
                    print(h)
        else:
            print("No hashes found.")
    else:
        print("Unable to retrieve the web page content.")

if __name__ == "__main__":
    main()
                            
