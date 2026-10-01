# phish-detector

Terminal phishing analyzer for Android / Termux. Analyzes URLs, emails, headers, and SMS/WhatsApp messages.

Built for Nigerian users — tuned for local scam patterns (BVN requests, fake bank SMS, CBN grant scams, telco promos, task scams).

## Features

- **URL analysis** — typosquats, homoglyphs, digit-substitution, suspicious TLDs, shortener expansion, `@`-trick detection, brand-as-subdomain
- **Email analysis** — SPF/DKIM/DMARC checks, reply-to mismatch, urgency/threat language, generic greeting detection
- **Header analysis** — sender authenticity, spoofing signals
- **Message analysis** — Nigerian scam keywords, BVN/OTP/PIN request detection
- **Reputation** — Google Safe Browsing, VirusTotal, URLhaus, URLScan, OpenPhish
- **Page inspection** — fetches the page, analyzes JavaScript, inspects TLS certificates, detects brand clones
- **Visual clone detection** — fingerprints known brand pages to catch impersonation

## Install

    pkg install python git -y
    pip install -r requirements.txt

## Usage

    python phishdetect.py

Pick an option from the menu. On first run, add your API keys via **Settings → API keys**.

## API keys (optional but recommended)

- Google Safe Browsing: https://console.cloud.google.com
- VirusTotal: https://www.virustotal.com
- URLhaus: https://urlhaus.abuse.ch

Free tier works without keys using URLScan + OpenPhish.

## License

MIT
