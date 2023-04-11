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
```
```bash
findomain -t target.com  | tee -a  findomain.txt
```
```bash
ffuf -u https://target.com -H "Host:FUZZ.target.com" -w -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

```
```bash
 assetfinder --subs-only target.com | tee -a assetfinderoutput
```
```bash
github-subdomains -d example.com -raw -o githubonlysubdomains.txt
```

```bash
python3 knockpy.py domain.com | tee -a knockpy.txt 
```




