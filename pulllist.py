import requests
from bs4 import BeautifulSoup
import json

# read search terms from file
with open("cve_ids.txt", "r") as f:
    search_terms = f.read().splitlines()
    with open("CVE_ID_output.txt", "w") as g:
    # loop through search terms and search on snyk.io
    # loop through search terms and search on snyk.io
        for search_term in search_terms:
            # make request to snyk.io search page
            url = f"https://security.snyk.io/vuln/?search={search_term}"
            response = requests.get(url)
            print(f"Searched_CVE = {search_term}")
            g.write(f"Searched_CVE = {search_term}")
            g.write("\n")
            # parse html response with beautifulsoup
            soup = BeautifulSoup(response.text, "html.parser")
            # find all <a> tags with class="vue--anchor" and print href values
            links = soup.find_all("a", {"class": "vue--anchor"})
            for link in links:
                href = link.get("href")
                full_url = f"https://security.snyk.io/{href}"
                sub_response = requests.get(full_url)
                if sub_response.status_code == 200 and href.startswith('vuln/'):
                    print(full_url)
                    g.write(full_url)
                    g.write("\n")
            if "PoC" in sub_response.text:
                print(f"PoC found {search_term}")
                g.write(f"PoC found {search_term}")
                g.write("\n")
            else:
                print(f"PoC not found {search_term}")
                g.write(f"PoC not found {search_term}")
                g.write("\n")
    # print response status code
    #print(f"Response status code: {response.status_code}")
            print("\n")  # print newline characters to separate output
            g.write("\n")
        print("\n")  # print newline characters to separate output
        g.write("\n")
print("CVE_ID_output.txt file is created")
