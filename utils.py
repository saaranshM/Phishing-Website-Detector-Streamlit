import base64
import re
from urllib.request import urlopen
import requests
import datetime
from dateutil.relativedelta import relativedelta
import whois
from bs4 import BeautifulSoup
import tldextract
import xml.etree.ElementTree as ET
import pandas as pd

regex = re.compile(
    r'^(?:http|ftp)s?://'  # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)


class PhishingUrl:

    def __init__(self, url):
        self.url = url
        try:
            self.resp = urlopen(url)
        except:
            self.resp = None

        if self.resp is not None:
            self.soup = BeautifulSoup(self.resp.read(), 'lxml')
        try:
            self.w = whois.whois(url)
        except:
            self.w = None

    def containsIP(self):
        """
        Checks if url contains IP address
        :return: -1 if containing ip address , 1 if does not contain ip address
        """
        if re.match(
                r"^(http|https)://\d+\.\d+\.\d+\.\d+\.*",
                self.url):
            return -1
        return 1

    def urlLengthChecker(self):
        """
        Checks the length of url
        """
        url_length = len(self.url)

        if url_length < 54:
            return 1
        elif url_length <= 75:
            return 0
        else:
            return -1

    def checkIfShortened(self):
        if self.resp is not None:
            if self.resp.geturl() != self.url:
                return -1
            return 0
        return -1

    def checkIgnoreSymbol(self):
        if "@" in self.url:
            return -1
        return 1

    def checkDoubleSlashPosition(self):
        pos = self.url.find("//")
        if pos > 7:
            return -1
        else:
            return 1

    def checkIfSeparated(self):
        if "-" in self.url:
            return -1
        return 1

    def countDots(self):
        mod_url = self.url.replace("www.", "")
        dot_count = mod_url.count(".")

        if dot_count <= 1:
            return 1
        elif dot_count <= 2:
            return 0
        else:
            return -1

    def verifyCertificate(self):
        try:
            res = requests.get(url=self.url, verify=True)
            return 1
        except Exception as e:
            return -1

    def checkDomainRegistrationLength(self):
        now_time = datetime.datetime.now()
        if self.w is not None:
            if type(self.w.creation_date) is list:
                domain_create_time = self.w.creation_date[0]
            else:
                domain_create_time = self.w.creation_date
            years = relativedelta(now_time, domain_create_time).years
            if years <= 1:
                return -1
            return 1
        return -1

    def checkHttpsPosition(self):
        pos = self.url.find("https")
        if pos > 0:
            return -1
        return 1

    def checkATags(self):
        ext = tldextract.extract(self.url)
        domain = ext.domain
        href_list = []
        neg_tags = 0
        if self.resp is not None:
            for link in self.soup.find_all('a'):
                href = link.get('href')
                href_list.append(href)
                if (domain not in href) and (not href.startswith('/')):
                    neg_tags += 1

            try:
                percentage_bad_href = neg_tags / len(href_list)
            except:
                percentage_bad_href = 0

            if percentage_bad_href < 0.31:
                return 1
            elif percentage_bad_href <= 0.67:
                return 0
            else:
                return -1
        return -1

    def checkTags(self):
        ext = tldextract.extract(self.url)
        domain = ext.domain
        content_list, link_href_list, script_scr_list = [], [], []
        neg_tags = 0

        if self.resp is not None:

            for link in self.soup.find_all('meta'):
                content = link.get('content')
                if content is not None and re.match(regex, content) is not None:
                    content_list.append(content)
                    if domain not in content:
                        neg_tags += 1

            for link in self.soup.find_all('link'):
                href = link.get('href')
                if re.match(regex, href) is not None:
                    link_href_list.append(href)
                    if domain not in href:
                        neg_tags += 1

            for link in self.soup.find_all('script'):
                src = link.get('src')
                if src is not None and re.match(regex, src) is not None:
                    script_scr_list.append(src)
                    if domain not in src:
                        neg_tags += 1

            total_list_len = len(content_list) + len(link_href_list) + len(script_scr_list)

            try:
                percentage_bad_links = neg_tags / total_list_len
            except:
                percentage_bad_links = 0

            if percentage_bad_links < 0.17:
                return 1
            elif percentage_bad_links <= 0.81:
                return 0
            else:
                return -1
        return -1

    def checkHost(self):
        if self.w is not None:
            domain_name = self.w.domain_name[1]
            if domain_name not in self.url:
                return -1
            return 1
        return -1

    def getRedirects(self, url):
        try:
            resp = urlopen(url)
            if resp.geturl() == url:
                return 0
            else:
                return 1 + self.getRedirects(resp.geturl())
        except:
            return 10

    def checkRedirects(self):
        redirects = self.getRedirects(self.url)

        if redirects <= 1:
            return 1
        elif redirects < 4:
            return 0
        return -1

    def checkRightClickDisable(self):
        if self.resp is not None:
            scripts = self.soup.find_all('script')
            for script in scripts:
                if script.string is not None and ("e.button == 2" or "event.button == 2") in script.string:
                    return -1
            return 1
        return -1

    def checkIframe(self):
        if self.resp is not None:
            iframe = self.soup.find("iframe")
            if iframe is not None:
                return -1
            return 1
        return -1

    def checkDomainAge(self):
        if self.w is not None:
            now_time = datetime.datetime.now()
            if type(self.w.creation_date) is list:
                domain_create_time = self.w.creation_date[0]
            else:
                domain_create_time = self.w.creation_date
            time = relativedelta(now_time, domain_create_time)
            if time.years >= 1 or time.months >= 6:
                return 1
            return -1
        return -1

    def checkRecords(self):
        if self.w is not None:
            return 1
        return -1

    def checkAlexaRank(self):
        try:
            rank_str = BeautifulSoup(urlopen("https://www.alexa.com/minisiteinfo/" + self.url),
                                     'html.parser').table.a.get_text()
            rank_int = int(rank_str.replace(',', ''))
            if rank_int and rank_int > 100000:
                return -1
            return 1
        except:
            return -1

    def checkPhishTank(self):
        headers = {
            'format': 'json',
        }
        new_check_bytes = self.url.encode()
        base64_bytes = base64.b64encode(new_check_bytes)
        base64_new_check = base64_bytes.decode('ascii')
        post_url = "http://checkurl.phishtank.com/checkurl/" + base64_new_check
        try:
            response = requests.request("POST", url=post_url, params=headers)
            root = ET.fromstring(response.text)
            if root[1][0][1].text == "true":
                return -1
            return 1
        except:
            return -1


def createPredictionDf(url):
    mod_url = "https://" + url
    obj = PhishingUrl(mod_url)
    url_dict = {
        "having_IP_Address": obj.containsIP(),
        "URL_Length": obj.urlLengthChecker(),
        "Shortining_Service": obj.checkIfShortened(),
        "having_At_Symbol": obj.checkIgnoreSymbol(),
        "double_slash_redirecting": obj.checkDoubleSlashPosition(),
        "Prefix_Suffix": obj.checkIfSeparated(),
        "having_Sub_Domain": obj.countDots(),
        "SSLfinal_State": obj.verifyCertificate(),
        "Domain_registeration_length": obj.checkDomainRegistrationLength(),
        "HTTPS_token": obj.checkHttpsPosition(),
        "URL_of_Anchor": obj.checkATags(),
        "Links_in_tags": obj.checkTags(),
        "Abnormal_URL": obj.checkHost(),
        "Redirect": obj.checkRedirects(),
        "RightClick": obj.checkRightClickDisable(),
        "Iframe": obj.checkIframe(),
        "age_of_domain": obj.checkDomainAge(),
        "DNSRecord": obj.checkRecords(),
        "web_traffic": obj.checkAlexaRank(),
        "Statistical_report": obj.checkPhishTank()
    }
    url_df = pd.DataFrame(url_dict, index=[0])
    return url_df


print(createPredictionDf("atsdddatffsd.weebly.com/").head())
