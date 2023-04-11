# Web-Application-Test
Checklist for Webapplication Recon

###  Automate Recon

```bash
./reconftw -d target.com -r 
```
```bash
python3 oneforall.py --target target.com run
```



###  Subdomain Enumeration.

```bash
subfinder -d target.com | tee -a subfinder.txt
subfinder -dL subfinder.txt | tee -a subfinders.txt
```
```bash
findomain -t target.com  | tee -a  findomain.txt
```
```bash
ffuf -u https://target.com -H "Host:FUZZ.target.com" -w -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt 

```
```bash
 assetfinder --subs-only target.com | tee -a assetfinder.txt
```
```bash
github-subdomains -d example.com -raw -o githubsubdomains.txt
```

```bash
python3 knockpy.py domain.com | tee -a knockpy.txt 
```

### Subdomain sorting

```bash
sort subfinders.txt findomain.txt assetfinder.txt githubsubdomains.txt knockpy.txt > target_subdomains.txt
```
```bash
cat target_subdomains.txt | httprobe | tee -a subdomains.txt 
```



###  Subdomain Takeover

```bash
cat subdomains.txt | nuclei -t /root/nuclei-template/takeovers
```
```bash
subzy -target /home/path/to/subdomains.txt
```


### ASN Enumerations

```bash
cat subdomains.txt | httpx -asn | tee -a asn.txt
```

```bash
asn -d domainname.com
```
```bash
asn -d IP
```

### ASN-Shodan Enumeration

```bash
asn:ASxxxx
```
### Shodan-Facet Analysis
```bash
asn:AS123XX http.title
```

### httpx 
- Status Code
```bash
cat subdomains.txt | httpx -mc 200,204,301,307,401,405,400,302 -sc
```
- IP Grabbing
```bash
cat subdomains.txt| httpx -probe -ip -cdn
```
- Probbing except 404 response code
```bash
cat subdomains.txt | httpx -sc -fc 404
```
- Grabbing Specific Path
```bash
| httpx -probe -sc -path "/robots.txt"
```


### Javascript Enumeration 

```bash
cat subdomains.txt | subjs | tee -a javascript.txt
```
```bash
while read url; do python3 /home/sumedh/tools/SecretFinder/SecretFinder.py -i $url -o cli ; done < "$1"
```

```bash
while read url ; do echo e "\n\n --------- URL: " $url "-----------" ;  python3 /home/sumedh/tools/LinkFinder/linkfinder.py -i $url -o cli; done < "$1"
```


```bash
cat subdomains.txt | httpx -sc -td -server -ip -cname -json -o httpx.json -mc 200,204,301,307,401,405,400,302,500 -x POST GET TRACE OPTIONS
```
```bash
cat httpx.json | jq
```

### Google dork : https://pentest-tools.com/information-gathering/google-hacking

```bash
• site:tesla.com -www -shop -share -ir -mfa
• site:pastebin.com "tesla.com"
• site:jsfiddle.net "tesla.com"
• site:codebeautify.org "tesla.com"
• site:codepen.io "tesla.com"
• site:tesla.com ext:php inurl:?
• site:openbugbounty.org inurl:reports intext:"yahoo.com"
• (site:tesla.com | site:teslamotors.com) & "choose file"
```
### Github dork 

```bash
• "site.com" API_key
• "site.com" secret_key
• "site.com" email
• "site.com" password
• "site.com" login
• "site.com" admin
• org:org_name "password"
• org:org_name "secret"
• user:username "password"
• user:username "secret"
```

### Port-Scanning

```bash
naabu -list subdomains.txt | tee -a naabu_port_number.txt
```
```bash
naabu -l subdomains.txt -rate 3000 -retries 1 -warm-up-time 0 -c 50 -top-ports 65535 - silent
```
```bash
cat subdoamins.txt | aquatone --ports xlarge
```
```bash
cat subdomains.txt  | naabu -silent 
```
```bash
echo ASxxxx | naabu 
```

### Content Discovery
- Make sure you change you wordlists. https://github.com/SumedhDawadi/wordlists
```bash
dirsearch -u https://domains.com -r -e php,html,js,txt,.zip.jsp,jspx,.bak
```

```bash
gobuster dir -u http://target.com -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt 
```
```bash
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/ -mc 200,204,301,307,401,405,400,302
```
- Change extensions 
```bash
ffuf -c -u https://target.com/FUZZ.html -w /usr/share/wordlists/bughunting/sdasdasdasd.txt -mc 200,204,301,307,401,405,400,302
```
- Bruteforce path  refering to nmap or naabu result for specific path
```bash
dirsearch -u http://target.com:8858/ -r  -w #use different wordlists
```

