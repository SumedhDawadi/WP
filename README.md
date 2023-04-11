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





























