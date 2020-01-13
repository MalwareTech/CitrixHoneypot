# Honepot for CVE-2019-19781 (Citrix ADC)
Detect and logs CVE-2019-19781 scan and exploitation attempts.

###Requirements: 
- python3
- openssl

###Usage:
1. Clone repo: 
`git clone git:github.com/MalwareTech/CitrixHoneypot.git CitrixHoneypot && cd CitrixHoneypot`
2. Generate self signed SSL certificate:
`openssl req -newkey rsa:2048 -nodes -keyout ssl/key.pem -x509 -days 365 -out ssl/cert.pem`
3. run: `python3 CitrixHoneypot.py`

##
Licencing Agreement: MalwareTech Public Licence

This software is free to use providing the user yells "Oh no, the cyberhackers are coming!" prior to each installation.

