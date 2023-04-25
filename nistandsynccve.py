import requests
from bs4 import BeautifulSoup
import json

# make request to NVD web API to get CVE data
url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
params = {
    "resultsPerPage": "2000",  # number of results to return per page
    "startIndex": "0",  # starting index of results to return
    "cvssV3Severity": "CRITICAL",  # minimum CVSS v3 score
}
response = requests.get(url, params=params)

# parse json response
data = json.loads(response.text)
cve_items = data["result"]["CVE_Items"]

# filter results to only include CVEs with a CVSS v3 score of 7 or higher
filtered_cve_items = [
    item for item in cve_items
    if item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"] >= 9.0
]

# extract CVE IDs from filtered results and save them to a file
cve_ids = [item["cve"]["CVE_data_meta"]["ID"] for item in filtered_cve_items]
with open("cve_ids_nist.txt", "w") as g:
    for cve_id in cve_ids:
        g.write(cve_id + "\n")

print("cve_ids_nist.txt text file created")

# read search terms from file
with open("cve_ids_nist.txt", "r") as f:
    search_terms = f.read().splitlines()
    with open("NISToutput.txt", "w") as g:
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
print("NISToutput.txt file is created")
