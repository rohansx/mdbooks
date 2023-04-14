# Server-code

## main.py

```python

import uvicorn
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from starlette.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
import v1

app = FastAPI()

app.add_middleware(
    CORSMiddleware, allow_origins=["http://localhost:8000"], allow_methods=["*"], allow_headers=["*"]
)

@app.get("/", tags=["root"])
def get_root():
    return RedirectResponse("/v1/")


app.include_router(
    v1.router,
    prefix="/v1",
    tags=["vulnerability scanning (version 1)"],
    responses={404: {"description": "Not found"}},
)


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="WAVS: Web App Vulnerability Scanner",
        version="0.0.1",
        description="""WAVS (Web App Vulnerability Scanner) is a tool to scan & test URLs for certain vulnerabilities & 
        security issues by simply inspecting the corresponding client-side website. The overall system would include a 
        virtual server with modules for detecting the different vulnerabilities, along with a proxy server, to direct 
        requests from a browser to the virtual server first while visiting a website. The proxy could warn the user before 
        redirecting to the website if some vulnerabilities are found during the scan done by our virtual server.
        \nWe identify & assess the following security issues that a website may suffer from: _Absence of Valid TLS Certificates_, 
        _Cross-Site Scripting (XSS)_, _Potential Phishing Attempts_ & _Open Redirection_
        """,
        routes=app.routes,
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png"
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

if __name__ == "__main__":
    uvicorn.run("main:app", host="localhost", port=9000)import uvicorn
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from starlette.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
import v1

app = FastAPI()

app.add_middleware(
    CORSMiddleware, allow_origins=["http://localhost:8000"], allow_methods=["*"], allow_headers=["*"]
)

@app.get("/", tags=["root"])
def get_root():
    return RedirectResponse("/v1/")


app.include_router(
    v1.router,
    prefix="/v1",
    tags=["vulnerability scanning (version 1)"],
    responses={404: {"description": "Not found"}},
)


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="WAVS: Web App Vulnerability Scanner",
        version="0.0.1",
        description="""WAVS (Web App Vulnerability Scanner) is a tool to scan & test URLs for certain vulnerabilities & 
        security issues by simply inspecting the corresponding client-side website. The overall system would include a 
        virtual server with modules for detecting the different vulnerabilities, along with a proxy server, to direct 
        requests from a browser to the virtual server first while visiting a website. The proxy could warn the user before 
        redirecting to the website if some vulnerabilities are found during the scan done by our virtual server.
        \nWe identify & assess the following security issues that a website may suffer from: _Absence of Valid TLS Certificates_, 
        _Cross-Site Scripting (XSS)_, _Potential Phishing Attempts_ & _Open Redirection_
        """,
        routes=app.routes,
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png"
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

if __name__ == "__main__":
    uvicorn.run("main:app", host="localhost", port=9000)

```

### 1. Open Redirection Detection
### 1.1 detector.py
```python
import warnings,ssl,requests
import urllib.parse as urlparse
warnings.filterwarnings('ignore')
ssl._create_default_https_context = ssl._create_unverified_context
#----------------------------------------------------------------------------------#

class OpenRedirectsDetector:
    def __init__(self):
        self.url = None
    
    def detect_or(self, url):
        if urlparse.urlparse(url).scheme == '':
            url = 'http://' + url
        self.url = url
        result = self.check()
        return result

    def check(self):
        values = ['url', 'rurl', 'u','next', 'link', 'lnk', 'go', 'target', 'dest', 'destination', 'redir', 
        'redirect_uri', 'redirect_url', 'redirect', 'view', 'loginto', 'image_url', 'return', 'returnTo', 'return_to',
        'continue', 'return_path', 'path']
        RedirectCodes = [i for i in range(300,311,1)]
        
        request = requests.Session()
        parsed = urlparse.urlparse(self.url)
        params = urlparse.parse_qsl(parsed.query)
        if(params):
            try:
                page = request.get(self.url, allow_redirects=False, timeout=10, verify=False, params='')
                page2 = request.get(self.url, allow_redirects=True, timeout=10, verify=False, params='')
                # print(page2.request.url)
                if page.status_code in RedirectCodes:
                    details = {}
                    for x,y in params:
                        if(x in values and y==page2.request.url):
                            details = {"parameter": x, "redirect_url": y }
                            break
                    if(details):
                        return {"result": "Header Based Redirection", "details": details}
                    elif('/r/' in self.url):
                        details = {"parameter": 'r'}
                        return {"result": "Header Based Redirection", "details": details}
                    else:
                        return {"result": "Open Redirection", "details": {}}
                elif page.status_code==404:
                    return {"result": "404 Not Found", "details": {}}
                elif page.status_code==403:
                    return {"result": "403 Forbidden", "details": {}}
                elif page.status_code==400:
                    return {"result": "400 Bad Request", "details": {}}
            except requests.exceptions.Timeout:
                return {"result": "TimeOut", "details": {"url": self.url}}
            except requests.exceptions.ConnectionError:
                return {"result": "Connection Error", "details": {"url": self.url}}

        payload = "https://www.google.co.in"
        query = ["url", "redirect_url"]
        for x in query:
            url = self.url+"?"+x+"="+payload            
            try:
                page = request.get(url, allow_redirects=False, timeout=10, verify=False, params='')
                page2 = request.get(url, allow_redirects=True, timeout=10, verify=False, params='')
                if(page.status_code in RedirectCodes and page2.request.url == payload):
                    return {"result": "Header Based Redirection", "details": {"parameter": x}}
                elif page.status_code==404:
                    return {"result": "404 Not Found", "details": {}}
                elif page.status_code==403:
                    return {"result": "403 Forbidden", "details": {}}
                elif page.status_code==400:
                    return {"result": "400 Bad Request", "details": {}}
            except requests.exceptions.Timeout:
                return {"result": "TimeOut", "details": {"url": self.url}}
            except requests.exceptions.ConnectionError:
                return {"result": "Connection Error", "details": {"url": self.url}}
        return {"result": "Not Vulnerable", "details": {}}


def main():
    o = OpenRedirectsDetector()
    # print(o.detect_or("https://bugslayers-cs416-open-redirect.herokuapp.com/?url=https://www.google.com"))
    # print(o.detect_or("https://medium.com/r/?url=https://phising-malicious.com"))
    # print(o.detect_or("google.co.in"))

if __name__ == "__main__":
    main()


```

### 2. Phishing Detection
### 2.1 detector.py
```python
import pickle
import os
from .extractor import WebsiteFeatureExtractor

class PhishingWebsiteDetector:
    def __init__(self, rel_model_path="./phishing_detection_model/phishing_website_detection_model.sav"):
        self.model = pickle.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), rel_model_path), "rb"))
        self.wfe = None

        self.interpretation = {
            -1: "Phishing",
            1: "Legitimate",
            0: "Suspicious"
        }

    def detect_phishing(self, url):
        self.wfe = WebsiteFeatureExtractor(url)
        
        precheck_res = self.__prechecks()
        
        if precheck_res["passed"]:
            feature_vec = self.wfe.extract_features()
            res = self.interpretation[self.model.predict([feature_vec])[0]]
            response = {
                "result": res
            }
            

            details = {
                "prechecks": "passed",
                "features": []
            }
            for feature, desc, val in zip(self.wfe.feature_names, self.wfe.feature_desc, feature_vec):
                details["features"].append({
                    "feature": feature,
                    "desc": desc,
                    "value": self.interpretation[val]
                })
            response["details"] = details
            
            return response
        else:
            return {"result": "Phishing", "details": {"prechecks": "failed", "failed_prechecks": precheck_res["details"]["failed_prechecks"]}}

    def __prechecks(self):
        res = {
            "passed": True,
            "details": {
                "failed_prechecks": []
            }
        }
        if self.wfe.soup == -999:
            res["passed"] = False
            res["details"]["failed_prechecks"].append("Unable to fetch website")
        else:
            if len(self.wfe.soup.find_all(["html"])) == 0:
                res["passed"] = False
                res["details"]["failed_prechecks"].append("No HTML Tag")
        
        return res
   


```
### 2.2 extractor.py
```python
import re
import os
import ssl, socket
import numpy as np
import datetime
import requests
import tldextract
import whois
import ipaddress
from googlesearch import search
from bs4 import BeautifulSoup
from dotenv import load_dotenv

import time

###########################################################################
############################ Feature Extractor ############################
###########################################################################

# Features to be extracted & stored in the following order:

# Index  Feature
# -----  -------------------------
# 0 	 SSLfinal_State
# 1 	 URL_of_Anchor
# 2 	 Links_in_tags
# 3 	 web_traffic
# 4 	 Prefix_Suffix
# 5 	 having_Sub_Domain
# 6 	 SFH
# 7 	 Request_URL
# 8 	 Links_pointing_to_page
# 9 	 Google_Index
# 10 	 URL_Length
# 11 	 DNSRecord
# 12 	 Domain_registeration_length
# 13 	 having_IP_Address
# 14 	 HTTPS_token
# 15 	 Page_Rank
# 16 	 age_of_domain
# 17 	 popUpWidnow
# 18 	 Iframe
# 19 	 on_mouseover
# --------------------------------

class WebsiteFeatureExtractor:
    def __init__(self, url):
        
        load_dotenv()
        
        # Converts the given URL into standard format
        self.url = url
        if not re.match(r"^https?", url):
            self.url = "https://" + url

        self.soup = self.getParsedResponse()
        self.subdomain, self.domain, self.suffix = self.parseDomain()
        self.whois_response = whois.whois(self.domain + "." + self.suffix)

        self.feature_names = [
            "SSLfinal_State",
            "URL_of_Anchor",
            "Links_in_tags",
            "web_traffic",
            "Prefix_Suffix",
            "having_Sub_Domain",
            "SFH",
            "Request_URL",
            "Links_pointing_to_page",
            "Google_Index",
            "URL_Length",
            "DNSRecord",
            "Domain_registeration_length",
            "having_IP_Address",
            "HTTPS_token",
            "Page_Rank",
            "age_of_domain",
            "popUpWidnow",
            "Iframe",
            "on_mouseover"
        ]
        self.feature_desc = [
            "Checks the age & issuer of SSL Certificate for website",
            "% of URLs in pointing to different domains or not to any webpage",
            "% of links in <script>, <link> & <meta> tags with different domains",
            "Popularity of a website using ranks from the Alexa database",
            "Prefixes or suffixes separated by (-) to the domain name",
            "Existence of multiple subdomains in the URL",
            "Check if the Server Form Handler has about:blank",
            "% of external objects within a webpage loaded from different domain",
            "Number of backlinks pointing to the page",
            "Check if the page is in Google's index or not",
            "Length of the URL (longish URLs are considered phishy)",
            "Existence of a DNS record for the webpage in the WHOIS database",
            "Registration period of domain & time until expiration",
            "Presence of an IP address (decimal/hex) in the domain part of URL",
            "Existence of HTTPS Token in the Domain Part of the URL",
            "Google's PageRank value for a webpage",
            "Time since creation of domain name of the website",
            "Existence of popups such as prompt() or alert() in the webpage",
            "Presence of <iframe> in a webpage to display additional webpages",
            "Use of onmouseover() event to change address bar contents"
        ]
        self.features = np.zeros(20, dtype=int)

    def extract_features(self):
        # Extract all features & return the feature vector
        # s = time.time()
        self.features[0] = self.checkSSLfinalState()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[1] = self.checkUrlOfAnchor()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[2] = self.checkLinksInTags()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[3] = self.checkWebTraffic()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[4] = self.checkPrefixSuffix()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[5] = self.checkHavingSubdomain()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[6] = self.checkSFH()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[7] = self.checkRequestUrl()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[8] = self.checkLinksPointingToPage()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[9] = self.checkGoogleIndex()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[10] = self.checkUrlLength()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[11] = self.checkDNSRecord()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[12] = self.checkDomainRegistrationLength()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[13] = self.checkHavingIPAddress()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[14] = self.checkHTTPSToken()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[15] = self.checkPageRank()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[16] = self.checkAgeOfDomain()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[17] = self.checkPopUpWindow()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[18] = self.checkIframe()
        # print("%.4f s" % (time.time() - s))
        # s=time.time()
        self.features[19] = self.checkOnMouseOver()
        # print("%.4f s" % (time.time() - s))

        return self.features
        

    ###################################################################
    ########################## Utility Functions ######################
    ###################################################################
    
    def getFeatureNames(self):
        return self.feature_names

    def getParsedResponse(self, url=None):
        url = url or self.url

        # Stores the response of the given URL
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
        except Exception:
            response = ""
            soup = -999

        return soup

    def parseDomain(self, url=None):
        url = url or self.url

        # Extracts domain from the given URL
        subdomain, domain, suffix = tldextract.extract(url)
        return subdomain, domain, suffix

    def getWhoisResponse(self, url=None):
        if url:
            _, domain, suffix = tldextract.extract(url)
            domain_name = domain + "." + suffix
            return whois.whois(domain_name)
        else:
            return self.whois_response

    def getDomainAndParsedResponse(self, url=None):
        if url == None:
            domain = self.domain
            soup = self.soup
        else:
            domain = self.parseDomain(url)[1]
            soup = self.getParsedResponse(url)
        return domain, soup

    def parseDatetimeString(self, datetime_str):
        return datetime.datetime.strptime(datetime_str, "%b %d %H:%M:%S %Y %Z")

    ###################################################################
    #################### Feature Extraction Functions #################
    ###################################################################

    # 0. SSLfinal_State
    def checkSSLfinalState(self, url=None):
        hostname = ".".join(self.parseDomain(url)[1:])
        reputed_issuers = ["IdenTrust", "DigiCert Inc", "Sectigo Limited", "GoDaddy.com, Inc.", "GlobalSign nv-sa", "Actalis S.p.A.", "Entrust, Inc.", "Google Trust Services", "Microsoft Corporation", "Amazon"]
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(5)
                s.connect((hostname, 443))
                cert = s.getpeercert()
            issuer = dict(x[0] for x in cert['issuer'])["organizationName"]
            issued_on = self.parseDatetimeString(cert["notBefore"])
            expires_on = self.parseDatetimeString(cert["notAfter"])
            cert_valid = (expires_on - datetime.datetime.today()).days > 0 and (datetime.datetime.today() - issued_on).days > 0
            
            if cert_valid:
                if issuer in reputed_issuers:
                    return 1
                else:
                    return 0
            else:
                return -1
        except Exception:
            return -1


    # 1. URL_of_Anchor
    def checkUrlOfAnchor(self, url=None):
        domain, soup = self.getDomainAndParsedResponse(url)
        i = 0
        unsafe=0
        if soup == -999:
            return -1
        else:
            for a in soup.find_all('a', href=True):
                if (not domain in a['href']) or a['href'].startswith("#") or "javascript" in a['href'].lower():
                    unsafe += 1
                i += 1
            try:
                percentage = unsafe / float(i) * 100
            except Exception:
                # No <a> tags with href found
                return 1

            if percentage < 31.0:
                return 1
            elif percentage <= 67.0:
                return 0
            else:
                return -1

    # 2. Links_in_tags
    def checkLinksInTags(self, url=None):
        domain, soup = self.getDomainAndParsedResponse(url)
        i=0
        success = 0
        if soup == -999:
            return -1
        else:
            for link in soup.find_all('link', href= True):
                if domain not in link['href']:
                    success = success + 1
                i = i+1

            for script in soup.find_all('script', src= True):
                if domain not in script['src']:
                    success = success + 1
                i = i+1
            try:
                percentage = success / float(i) * 100
            except Exception:
                return 1

            if percentage < 17.0 :
                return 1
            elif percentage <= 81.0:
                return 0
            else :
                return -1

    # 3. web_traffic
    def checkWebTraffic(self, url=None):
        url = url or self.url
        try:
            r = requests.get('http://tools.mercenie.com/alexa-rank-checker/api/?format=json&urls=' + url, timeout=2)
            data = r.json()
            rank = int(data['alexaranks']['first']['alexarank']['0'])

            if rank < 100000:
                return 1
            else:
                return 0
        except Exception:
            return -1

    # 4. Prefix_Suffix
    def checkPrefixSuffix(self, url=None):
        domain = self.getDomainAndParsedResponse(url)[0]
        if "-" in domain:
            return -1
        else:
            return 1

    # 5. having_Sub_Domain
    def checkHavingSubdomain(self, url=None):
        if url == None:
            subdomains = self.subdomain.split(".")
        else:
            subdomains = tldextract(url)[0].split(".")

        if "www" in subdomains:
            subdomains.remove("www")
        if len(subdomains) == 0:
            return 1
        elif len(subdomains) == 1:
            if subdomains[0] == "":
                return 1
            else:
                return 0
        else:
            return -1

    # 6. SFH
    def checkSFH(self, url=None):
        domain, soup = self.getDomainAndParsedResponse(url)
        sfh_empty = 0
        sfh_other_domain = 0
        for form in soup.find_all('form', action= True):
            if form['action'] =="" or form['action'] == "about:blank" :
                sfh_empty += 1
            elif domain not in form['action']:
                sfh_other_domain += 1
        
        if sfh_empty > 0:
            return -1
        elif sfh_other_domain > 0:
            return 0
        else:
            return 1

    # 7. Request_URL
    def checkRequestUrl(self, url=None):
        domain, soup = self.getDomainAndParsedResponse(url)
        i = 0
        success = 0
        
        if soup == -999:
            return -1
        
        else:
            for elem in soup.find_all(["img", "audio", "embed", "iframe", "video"]):
                # Check for <source> tags within the media elements
                for src in elem.find_all("source"):
                    if domain in src['src']:
                        success += 1
                    i += 1
                
                # Check for src attribute of the media elements
                if elem.has_attr("src"):
                    if domain in elem['src']:
                        success += 1
                    i += 1

            try:
                percentage = success/float(i) * 100
            except Exception:
                return 1

            if percentage < 22.0 :
                return 1
            elif percentage <= 61.0:
                return 0
            else :
                return -1

    # 8. Links_pointing_to_page
    def checkLinksPointingToPage(self, url=None):
        url = url or self.url
        try:
            data = {"urlo": url}
            r = requests.post("http://tools.mercenie.com/moz-checker/", data=data, timeout=2)
            soup = BeautifulSoup(r.text, 'html.parser')

            for row in soup.find_all("tr"):
                row_data = row.find_all("td")
                if len(row_data) == 2 and row_data[0].text == "Number of Backlinks":
                    num_backlinks = int(row_data[1].text)
            
            if num_backlinks == 0:
                return -1
            elif num_backlinks <= 2:
                return 0
            else:
                return 1

        except Exception:
            return -1

    # 9. Google_Index
    def checkGoogleIndex(self, url=None):
        url = url or self.url
        try:
            results = search(url)
            if url in results:
                return 1
            else: 
                return -1
        except Exception:
            return -1

    # 10. URL_Length
    def checkUrlLength(self, url=None):
        url = url or self.url
        if len(url) < 54:
            return 1
        elif len(url) >= 54 and len(url) <= 75:
            return 0
        else:
            return -1

    # 11. DNSRecord
    def checkDNSRecord(self, url=None):
        whois_response = self.getWhoisResponse(url)
        if "domain_name" not in whois_response.keys() or whois_response["domain_name"] == None:
            return -1
        else:
            return 1

    # 12. Domain_registeration_length
    def checkDomainRegistrationLength(self, url=None):
        if self.checkDNSRecord(url) == -1:
            return -1

        whois_response = self.getWhoisResponse(url)
        
        # Obtain the domain creation date
        if "creation_date" not in whois_response.keys():
            return -1
        if type(whois_response["creation_date"]) == datetime.datetime:
            creation_date = whois_response["creation_date"]
        elif type(whois_response["creation_date"]) == list:
            creation_date = whois_response["creation_date"][0]
        
        # Obtain the domain expiration date
        if "expiration_date" not in whois_response.keys():
            return -1
        if type(whois_response["expiration_date"]) == datetime.datetime:
            expiration_date = whois_response["expiration_date"]
        elif type(whois_response["expiration_date"]) == list:
            expiration_date = whois_response["expiration_date"][0]
        
        reg_len = expiration_date - creation_date
        if reg_len.days <= 365:                     # Less than 1 year
            return -1
        else:
            return 1

    # 13. having_IP_Address
    def checkHavingIPAddress(self, url=None):
        domain= self.getDomainAndParsedResponse(url)[0]
        try:
            resp = ipaddress.ip_address(domain)
            return -1
        except Exception:
            return 1

    # 14. HTTPS_token
    def checkHTTPSToken(self, url=None):
        if url:
            subdomain, domain, _ = tldextract.extract(url)
        else:
            subdomain = self.subdomain
            domain = self.domain

        if "https" in subdomain or "https" in domain:
            return -1
        else:
            return 1

    # 15. Page_Rank
    def checkPageRank(self, url=None):
        if url:
            _, domain, suffix = self.parseDomain(url)
            domain_name = domain + "." + suffix
        else:
            domain_name = self.domain + "." + self.suffix
        
        try:
            page_rank_url = "https://openpagerank.com/api/v1.0/getPageRank?domains[]=" + domain_name
            headers = {"API-OPR": os.getenv("OPR_API_KEY")}
            r = requests.get(page_rank_url, headers=headers, timeout=2).json()
            pr = float(r["response"][0]["page_rank_decimal"])/10
        except Exception:
            return -1

        if pr < 0.2:
            return -1
        else:
            return 1

    # 16. age_of_domain
    def checkAgeOfDomain(self, url=None):
        if self.checkDNSRecord(url) == -1:
            return -1

        whois_response = self.getWhoisResponse(url)

        # Obtain the domain creation date
        if "creation_date" not in whois_response.keys():
            return -1
        if type(whois_response["creation_date"]) == datetime.datetime:
            creation_date = whois_response["creation_date"]
        elif type(whois_response["creation_date"]) == list:
            creation_date = whois_response["creation_date"][0]
        
        # Obtain today's date
        today = datetime.datetime.today()
        
        age = (today - creation_date).days
        if age >= 182:
            return 1
        else:
            return -1

    # 17. popUpWindow
    def checkPopUpWindow(self, url=None):
        soup = self.getDomainAndParsedResponse(url)[1]
        if len(re.findall(r"(prompt\()|(alert\()", str(soup))) > 0:
            return -1
        else:
            return 1
    
    # 18. Iframe
    def checkIframe(self, url=None):
        soup = self.getDomainAndParsedResponse(url)[1]
        if len(soup.find_all("iframe", frameborder="0")) > 0:
            return -1
        else:
            return 1

    # 19. on_mouseover
    def checkOnMouseOver(self, url=None):
        soup = self.getDomainAndParsedResponse(url)[1]
        if len(re.findall(r"onmouseover", str(soup))) > 0:
            return -1
        else:
            return 1





```

    

### 3. TLS Certificate detection
### 3.1 cert_checker.py
```python

import datetime
import select
import socket
import sys
import OpenSSL
import json

class Domain(str):
    def __new__(cls, domain):
        host = domain
        port = 443
        connection_host = host
        result = str.__new__(cls, host)
        result.host = host
        result.connection_host = connection_host
        result.port = port
        return result

class CertChecker:
    def __init__(self):
        pass

    def get_cert_from_domain(self, domain):
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        sock = socket.socket()
        sock.settimeout(5)
        wrapped_sock = OpenSSL.SSL.Connection(ctx, sock)
        wrapped_sock.set_tlsext_host_name(domain.host.encode('ascii'))
        wrapped_sock.connect((domain.connection_host, 443))
        while True:
            try:
                wrapped_sock.do_handshake()
                break
            except OpenSSL.SSL.WantReadError:
                select.select([wrapped_sock], [], [])
        return wrapped_sock.get_peer_cert_chain()

    def get_domain_certs(self, domains):
        domain = Domain(domains)
        try:
            data = self.get_cert_from_domain(domain)
        except Exception as e:
            data = e
        return data

    def validate_cert(self, cert_chain):
        msgs = []
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        ctx.set_default_verify_paths()
        cert_store = ctx.get_cert_store()
        for index, cert in reversed(list(enumerate(cert_chain))):
            sc = OpenSSL.crypto.X509StoreContext(cert_store, cert)
            try:
                sc.verify_certificate()
            except OpenSSL.crypto.X509StoreContextError as e:
                msgs.append(
                    ('error', "Validation error '%s'." % e))
            if index > 0:
                cert_store.add_cert(cert)
        return msgs


    def check(self, domain,domain_certs,utcnow):
        msgs = []
        results = []

        earliest_expiration = None
        if domain_certs is None: return (msgs, earliest_expiration, None)
        if isinstance(domain_certs, Exception): 
            domain_certs = "".join(traceback.format_exception_only(type(domain_certs),domain_certs)).strip()
        msgs = self.validate_cert(domain_certs)
        for i, cert in enumerate(domain_certs):
            result = {}
            subject = cert.get_subject().commonName
            result["subject"] = subject
            expires = datetime.datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
            result["expires"] = str(expires)

            if expires:
                if earliest_expiration is None or expires < earliest_expiration:
                    earliest_expiration = expires
            issued_level = "info"
            issuer = cert.get_issuer().commonName
            if issuer:
                if issuer.lower() == "happy hacker fake ca":
                    issued_level = "error"
            else:
                issued_level = 'warning'    
            msgs.append((issued_level, "Issued by: %s (subject: %s)" % (issuer, subject)))
            result["issuer"] = issuer

            results.append(result)

            if i < len(domain_certs) - 1:
                sign_cert = domain_certs[i+1]
                subject = sign_cert.get_subject().commonName
                if issuer != subject:
                    msgs.append(
                        ('error', "The certificate sign chain subject '%s' doesn't match the issuer '%s'." % (subject, issuer)))

            sig_alg = cert.get_signature_algorithm()
            if sig_alg.startswith(b'sha1'):
                msgs.append(('error', "Unsecure signature algorithm %s (subject: %s)" % (sig_alg, subject)))
            if expires < utcnow:
                msgs.append(
                    ('error', "The certificate has expired on %s (subject: %s)" % (expires, subject)))
            elif expires < (utcnow + datetime.timedelta(days=15)):
                msgs.append(
                    ('warning', "The certificate expires on %s (%s) (subject: %s)" % (
                        expires, expires - utcnow, subject)))
            else:
                delta = ((expires - utcnow) // 60 // 10 ** 6) * 60 * 10 ** 6
                msgs.append(
                    ('info', "Valid until %s (%s)." % (expires, delta)))
        
        return (msgs, earliest_expiration, results)


    def checkCertChain(self, domain):
        domain = domain.replace("http://","")
        domain = domain.replace("https://","")
        domain = domain.split('/')[0]
        domain_certs = self.get_domain_certs(domain)

        if isinstance(domain_certs, Exception):
            output = {
                "result": "Invalid",
                "errors": ["Unable to obtain certficate chain"],
                "warnings": [],
                "details": []
            }
            return output

        utcnow = datetime.datetime.now()
        (msgs, earliest_expiration, results) = self.check(domain,domain_certs,utcnow)

        warnings = []
        output = {}
        output["details"] = results
        errors = []
        for level, msg in msgs:
            if level == 'error': 
                errors.append(msg)
            elif level == 'warning':
                warnings.append(msg)
        
        output["errors"] = errors
        output["warnings"] = warnings

        if len(errors) > 0:
            output["result"] = "Invalid" 
        elif len(warnings) > 0:
            output["result"] = "Valid (with Warnings)"
        else: output["result"] = "Valid"
        
        return output


```

### 4. XSS Detection
### 4.1 main.py

```python
import uvicorn
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from starlette.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
import v1

app = FastAPI()

app.add_middleware(
    CORSMiddleware, allow_origins=["http://localhost:8000"], allow_methods=["*"], allow_headers=["*"]
)

@app.get("/", tags=["root"])
def get_root():
    return RedirectResponse("/v1/")


app.include_router(
    v1.router,
    prefix="/v1",
    tags=["vulnerability scanning (version 1)"],
    responses={404: {"description": "Not found"}},
)


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="WAVS: Web App Vulnerability Scanner",
        version="0.0.1",
        description="""WAVS (Web App Vulnerability Scanner) is a tool to scan & test URLs for certain vulnerabilities & 
        security issues by simply inspecting the corresponding client-side website. The overall system would include a 
        virtual server with modules for detecting the different vulnerabilities, along with a proxy server, to direct 
        requests from a browser to the virtual server first while visiting a website. The proxy could warn the user before 
        redirecting to the website if some vulnerabilities are found during the scan done by our virtual server.
        \nWe identify & assess the following security issues that a website may suffer from: _Absence of Valid TLS Certificates_, 
        _Cross-Site Scripting (XSS)_, _Potential Phishing Attempts_ & _Open Redirection_
        """,
        routes=app.routes,
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png"
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

if __name__ == "__main__":
    uvicorn.run("main:app", host="localhost", port=9000)

```





