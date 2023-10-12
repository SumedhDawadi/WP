# Web-Application-Test
Checklist for Webapplication Recon

###  Automate Recon

```bash
./reconftw -d target.com -r 
```
```bash
python3 oneforall.py --target target.com run
```

### Acquisitions for wide scope range
```bash
1. Crunchbase for finding acquisitions
2. ChatGPT for finding acquisitions
3. https://bgp.he.net/ for finding ASN and IP-Range
```
### Wordpress Scanner

```bash
wpscan --url http://192.168.145.133/wordpress -e vt,tt,u,ap
```
###  Subdomain Enumeration.

```bash
subfinder -d target.com | tee -a subfinder.txt
subfinder -dL subfinder.txt | tee -a subfinders.txt
```

### Using whois for finding IP's
```bash
apt-get install whois
```
```bash
whois -h whois.radb.net  -- '-i origin AS714' | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq -u
```
```bash
subfinder -d target.com -silent -o subs.txt | httpx -title -content-length -status-code -silent
```
findomain -t target.com  | tee -a  findomain.txt
```
```bash
ffuf -u https://target.com -H "Host:FUZZ.target.com" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt 

```

## Using amass for more scope 
```bash
amass enum -brute -w /root/hugeDNS.txt -d target.com -o result.txt
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
```bash
amass enum -v -src -ip -brute -min-for-recursive 2 -d target.com | tee -a amass.txt
```
### Extracting IP's from Subdomains
```bash
cat subdoamins.txt | xargs -n1 host | grep "has address" | cut -d" " -f4 | sort -u > ips.txt
```
## Using More IP's
```bash
cat subdoamins.txt | xargs -n1 host | grep "has address" | cut -d" " -f4 | sort -u > ips.txt
```
### Subdomain sorting

```bash
sort subfinders.txt findomain.txt assetfinder.txt githubsubdomains.txt amass.txt knockpy.txt > target_subdomains.txt
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
- https://github.com/nitefood/asn
```bash
asn -d domainname.com
```
```bash
asn -d IP
```
#### Shodan Query : https://mr-koanti.github.io/shodan
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
cat subdomains.txt | httpx -probe -sc -path "/robots.txt"
```


### Javascript Enumeration. Refer to https://github.com/B-and-w-sec/shell-scripts

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
```bash
cat domains.txt | katana | grep js | httpx -mc 200 | tee js.txt
```
```bash
nuclei -l js.txt -t ~/nuclei-templates/exposures/ -o js_bugs.txt
```
```bash
file="js.txt"

# Loop through each line in the file
while IFS= read -r link
do
    # Download the JavaScript file using wget
    wget "$link"
done < "$file"

AGAIN, 

grep -r -E "aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|aws_secret_key|aws key|password|ftp password|jdbc|db|sql|secret jet|config|admin|pwd|json|gcp|htaccess|.env|ssh key|.git|access key|secret token|oauth_token|oauth_token_secret|smtp" *.js
```
### Google dork : https://pentest-tools.com/information-gathering/google-hacking OR http://seckrd.com/google-hacking and https://taksec.github.io/google-dorks-bug-bounty/

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
cat subdomains.txt | xargs -n1 host | grep "has address" | cut -d" " -f4 | sort -u > ips.txt
```
```bash
masscan -iL ips.txt -p0-65535 --rate=10000 -oL scan.txt
```
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

### Endpoint Extraction 

```bash
cat subdomains.txt | katana | tee -a katana.txt
```
```bash
cat subdomains.txt | gauplus | tee -a gauplus.txt
```
```bash
cat subdomains.txt | waybackurl | tee -a wayback.txt
```
```bash
cat subdomains.txt | hakrawler | tee  -a hakrawler.txt
```
```bash
cat subdomains.txt | gau --blacklist png,jpg,jpeg,img,svg,mp3,mp4,eot,woff1,woff2,css | tee -a extension_extractor.txt
```
### Sorting Endpoints
```bash
sort katana.txt gauplus.txt wayback.txt hakrawler.txt extension_extractor.txt > endpoints.txt
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

### GF Pattern
- Use GF template one by one
```bash
cat endpoints.txt | gf -list
```

### Nuclei 
- Use Cent as a custom Nuclei Templates. https://github.com/xm1k3/cent
```bash
cat subdoamins.txt | nuclei 
```
```bash
cat endpoints.txt | nuclei
```
```bash
nuclei -u https://targets.com:8858 -t /root/nuclei-template/
```
# Use Burpsuite for further exploitation.



