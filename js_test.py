import requests
from bs4 import BeautifulSoup

url = "http://rest.vulnweb.com"

response = requests.get(url, timeout=10)

print("Status Code:", response.status_code)

soup = BeautifulSoup(response.text, "html.parser")

with open("output/links.txt","w") as f:
    for link in soup.find_all("a"):
        href = link.get("href")
        if href:
            print(href)
            f.write(href + "\n")
