# Honepot for CVE-2019-19781 (Citrix ADC)
Detect and log CVE-2019-19781 scan and exploitation attempts.

### Requirements: 
- python3
- openssl

### Usage:
1. Clone repo: 
`git clone https://github.com/MalwareTech/CitrixHoneypot.git CitrixHoneypot && cd CitrixHoneypot`
2. Make ssl and logs directory: `mkdir logs ssl`
3. Generate self signed SSL certificate:
`openssl req -newkey rsa:2048 -nodes -keyout ssl/key.pem -x509 -days 365 -out ssl/cert.pem`
4. run: `python3 CitrixHoneypot.py`

## Docker Usage (Optional)
1. `docker build -t citrixhoneypot .`
2. `docker run -d -p 443:443 -v /<insert-homepath>/CitrixHoneypot:/CitrixHoneypot -w /CitrixHoneypot citrixhoneypot`

## Licencing Agreement: MalwareTech Public Licence
This software is free to use providing the user yells "Oh no, the cyberhackers are coming!" prior to each installation.

