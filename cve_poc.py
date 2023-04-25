import os
import requests
from bs4 import BeautifulSoup
import json

print("################################")
print("#####Enter CVE-XXXX-XXXXX ######")
print("#####OR Enter list ############# ")
print("###Press Enter for All #########")
print("################################")

search_term = input("\n Enter a CVE: ")


if search_term == "":
    print("Running nistandsynccve.py")
    os.system("python nistandsynccve.py")

elif search_term == "list":
    print("Running pulllist.py")
    os.system("python pulllist.py")


else:
    # do something with the CVE input
    with open("NISToutput.txt", "w") as g:
        url = f"https://security.snyk.io/vuln/?search={search_term}"
        response = requests.get(url)
        print(f"Searched_CVE = {search_term}")
        g.write(f"Searched_CVE = {search_term}")
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
print("NISToutput.txt file is created")
