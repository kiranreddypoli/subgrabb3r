import requests
from bs4 import BeautifulSoup
import ssl
import OpenSSL
from pyasn1.codec.der import decoder
from ndg.httpsclient.subj_alt_name import SubjectAltName


def banner():
    print("""
 #####                                                    #####         
#     # #    # #####   ####  #####    ##   #####  #####  #     # #####  
#       #    # #    # #    # #    #  #  #  #    # #    #       # #    # 
 #####  #    # #####  #      #    # #    # #####  #####   #####  #    # 
      # #    # #    # #  ### #####  ###### #    # #    #       # #####  
#     # #    # #    # #    # #   #  #    # #    # #    # #     # #   #  
 #####   ####  #####   ####  #    # #    # #####  #####   #####  #    #
                * Coded By Kiran Kumar Reddy Poli.
                * LinkedIn: /kiran-kumar-reddy-poli
    """)


def google(url):
    try:
        session = requests.get(url)
        data = requests.get(url, cookies=session.cookies)
        if data.status_code == 503 and str(data.url[:data.url.find(":")]) == 'https':
            google(url.replace("https://", "http://"))

        soup = BeautifulSoup(data.content, 'lxml')
        for link in soup.find_all('a', href=True):
            if link['href'].split("=")[0] == "/url?q" and "webcache.googleusercontent.com" not in \
                    link['href'].split("=")[1].split("&")[0]:
                if link['href'].split("=")[1].split("&")[0].split("/")[2] not in subdomains:
                    subdomains.append(link['href'].split("=")[1].split("&")[0].split("/")[2])
                    print("Sub-domain found from Google: " + link['href'].split("=")[1].split("&")[0].split("/")[2])

        for div in soup.body.find_all('div'):
            if div.get('id') == 'foot':
                for link in div.table.find_all('a', href=True):
                    if link.text == "Next":
                        google("https://www.google.co.in" + link['href'])
    except:
        pass


def crt(url):
    try:
        data = requests.get(url)
        for (key, value) in enumerate(data.json()):
            if value['name_value'] not in subdomains:
                subdomains.append(value['name_value'])
                print("Sub-domain found from crt: " + value['name_value'])
    except:
        pass


def virus_total(url):
    data = requests.get(url, allow_redirects=True)
    soup = BeautifulSoup(data.content, 'lxml')
    for link_div in soup.findAll('div', {'id': 'observed-subdomains'}):
        for link in link_div.findAll('a', href=True):
            if link.text.strip() not in subdomains:
                subdomains.append(link.text.strip())
                print("Sub-domain found from virusTotal: " + link.text.strip())


def ipv4info(url):
    data = requests.get(url)
    soup = BeautifulSoup(data.content, 'lxml')
    for tr in soup.findAll('tr'):
        if tr.find('td').text == "Domains":
            for a in tr.findAll('a'):
                if a.text.strip().endswith(domain) and a.text.strip() not in subdomains:
                    subdomains.append(a.text.strip())
                    print("Sub-domain found from ipv4info: " + a.text.strip())
                if a.get('href')[:5] == "/dns/":
                    ipv4info_subdomain_extractor("http://ipv4info.com/subdomains" + a.get('href')[4:] + ".html")


def ipv4info_subdomain_extractor(url):
    data = requests.get(url)
    soup = BeautifulSoup(data.content, 'lxml')
    try:
        table = soup.find('table', {"class": "TB2_90pr"})
        for a in table.findAll('a'):
            if a.get('href')[:5] == "/dns/" and a.get('href').split("/")[3] not in subdomains:
                subdomains.append(a.get('href').split("/")[3])
            elif a.text == "Next page":
                ipv4info_subdomain_extractor("http://ipv4info.com" + a.get('href'))
    except:
        pass


def bing(url):
    try:
        data = requests.get(url)
        soup = BeautifulSoup(data.content, 'lxml')
        ol = soup.find('ol', {"id": "b_results"})
        for li in ol.findAll('li'):
            for a in li.findAll('a', href=True):
                if a.get('href')[:7] != "/search" and a.get('href').split('/')[2] != 'go.microsoft.com' \
                         and a.get('href').split('/')[2] not in subdomains:
                    subdomains.append(a.get('href').split('/')[2])
                    print("Sub-domain found from bing: " + a.get('href').split('/')[2])
        nav = ol.find('nav')
        for a in nav.findAll("a"):
            if a.text == 'Next':
                bing("https://www.bing.com" + a.get('href'))
    except:
        pass


def dnsdumpster(target):
    dnsdumpster_url = 'https://dnsdumpster.com/'
    req = requests.get(dnsdumpster_url)
    soup = BeautifulSoup(req.content, 'html.parser')
    csrf_middleware = soup.findAll('input', attrs={'name': 'csrfmiddlewaretoken'})[0]['value']
    cookies = {'csrftoken': csrf_middleware}
    headers = {'Referer': dnsdumpster_url}
    data = {'csrfmiddlewaretoken': csrf_middleware, 'targetip': target}
    req = requests.post(dnsdumpster_url, cookies=cookies, data=data, headers=headers)
    soup = BeautifulSoup(req.content, 'html.parser')
    tables = soup.findAll('tr')
    for table in tables:
        if table.find('td', {'class': "col-md-4"}) and \
                str(table.find('td', {'class': "col-md-4"})).split('<br/>')[0].split('>')[1] not in subdomains:
            subdomains.append(str(table.find('td', {'class': "col-md-4"})).split('<br/>')[0].split('>')[1])
            print("Sub-domain found from dnsdumpster: " +
                  str(table.find('td', {'class': "col-md-4"})).split('<br/>')[0].split('>')[1])


def transparency(url):
    try:
        data = requests.get(url).content
        data = eval(data[5:])
        for record in data[0][1]:
            if record[1] not in subdomains:
                subdomains.append(record[1])
                print("Sub-domain found from Google-transparency: " + record[1])
        if data[0][3][1] != 'null':
            transparency(
                "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch/page?p=" +
                data[0][3][1])
    except:
        pass


def subject_alt_name(target, port=443):
    general_names = SubjectAltName()
    try:
        cert = ssl.get_server_certificate((target, port))
    except:
        return
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    for extension_id in range(0, x509.get_extension_count()):
        ext = x509.get_extension(extension_id)
        ext_name = ext.get_short_name().decode('utf-8')
        if ext_name == 'subjectAltName':
            ext_data = ext.get_data()
            decoded_dat = decoder.decode(ext_data, asn1Spec=general_names)
            for name in decoded_dat:
                if isinstance(name, SubjectAltName):
                    for entry in range(len(name)):
                        component = name.getComponentByPosition(entry)
                        if str(component.getComponent()) not in subdomains:
                            subdomains.append(str(component.getComponent()))
                            print("Sub-domain found from subject_alt_name: " + str(component.getComponent()))


def ctsearch(url):
    try:
        data = requests.get(url).content
        data = eval(data)
        for item in data:
            if item['subjectDN'].split(',')[0].split('=')[1] not in subdomains:
                subdomains.append(item['subjectDN'].split(',')[0].split('=')[1])
                print("Sub-domain found from ctsearch: " + item['subjectDN'].split(',')[0].split('=')[1])
    except:
        pass

banner()
domain = input("Enter domain: ")
subdomains = []
google("https://www.google.co.in/search?num=100&q=site:" + domain)
google("https://www.google.co.in/search?num=100&q=site:*." + domain)
google("https://www.google.co.in/search?num=100&q=site:*.*." + domain)
crt("https://crt.sh/?q=%." + domain + "&output=json")
virus_total("https://www.virustotal.com/es/domain/" + domain + "/information/")
ipv4info("http://ipv4info.com/?act=check&ip=" + domain)
bing("https://www.bing.com/search?q=site:" + domain)
bing("https://www.bing.com/search?q=site:*." + domain)
bing("https://www.bing.com/search?q=site:*.*." + domain)
dnsdumpster(domain)
transparency(
    "https://transparencyreport.google.com/transparencyreport/api/v3/"
    "httpsreport/ct/certsearch?include_subdomains=true&domain=" + domain)
subject_alt_name(domain)
ctsearch("https://ctsearch.entrust.com/api/v1/certificates?fields=subjectDN&domain=" + domain)
with open(domain + '_subdomains.txt', 'a') as file:
    for subdomain in subdomains:
        file.write("%s\n" % subdomain)
print("Subdomains stored in the file: " + domain + "_subdomains.txt")
