# OSINT-Tools
Collection of tools that might make the life of SOC analysts or IR analysts a little easier


IoC_analyzer.py is a multipurpose tool that aims to facilitate the rapid triaging of IoCs utiling various platforms.
The first version has been tested with the following tools:
- Virus Total
- AbuseIPDB
- ip-api.com (No API key is needed)
- Malware Bazaar
- URLhaus

Please note that the tool has been tested with single IoC and up to 8 IoCs, this is due to API limitations when utilizing the free API, for example VT has API limitations, for more information please read the API documentations and modify the script based on your needs as well as based on your accounts
Please note that the time intervals between requests have been choosed to respect the Platforms' APIs without abusing the relevant resources.

Also, within the script there are integrations with the following tools:
-Anyrun
-securitytrails
-Hybrid Analysis
-Shodan

These integrations have not been tested as i do not own any of the above API keys

This script has the following usefull features:
- 🔍 Auto-detect input type: IP, Domain, Hash (MD5/SHA1/SHA256), or URL.
- 🔗 Queries 8+ Threat Intelligence platforms.
- 📁 Supports single IOCs or batch input via text files.
- 💡 Built-in rate-limiting per service to avoid throttling.
- 🔐 API key support via config file or environment variables.
- 📊 Human-readable or JSON output for automation/SIEM integration.

For the test I utilized a configuration file that contains the relevant API keys.

Regarding its usage, we will check every single IoC that this script supports starting from the hash.

## POC 
For example, 
