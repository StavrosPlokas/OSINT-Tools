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

# POC 
## Hash analysis
For example, using the IoC_analyzer.py script we can analyze a hash. The script autodetect can the IoCs that are provided by the user. Although the user can state what type he wants to examine.
The following commands can be utilized direct from the CLI.
```
python3 IoC_analyzer.py -c config.json -t hash 7c59ac829ee7bdd43413539d2a8a6a968d2fb35fe56b935b5f0a4baef8dcdb25
python3 IoC_analyzer.py -c config.json 7c59ac829ee7bdd43413539d2a8a6a968d2fb35fe56b935b5f0a4baef8dcdb25
```
Botf of these commands have the following output:
<img width="1704" height="695" alt="image" src="https://github.com/user-attachments/assets/488371c4-f96c-4da8-aba5-e9811f8417b5" />
By default, the script will store the ouput of the last command to analysis_results.json file, but the user can also choose the file he wants to ouput the results.

This can be done by utiling the -o or --output flag.

The following command is the relevant example that the results are outputed to a json file with name the hash that was used for the examination.
```
python3 IoC_analyzer.py -c config.json -t hash 7c59ac829ee7bdd43413539d2a8a6a968d2fb35fe56b935b5f0a4baef8dcdb25 -o 7c59ac829ee7bdd43413539d2a8a6a968d2fb35fe56b935b5f0a4baef8dcdb25.json
```
Please note that the ouputted files contain additionall information regarding the examination of the hash.
For example, the json file contains the vendors that have flagged this file as malicious as illustrated on the following figure.
<img width="1183" height="918" alt="image" src="https://github.com/user-attachments/assets/671bde84-c79b-4052-8e7a-4f5852b9e820" />

Finally, a user can analyze multiple hashes, as POC the following figure illustrates the hashes that were choosed for examination.
<img width="557" height="60" alt="image" src="https://github.com/user-attachments/assets/328a29d8-4fec-46b2-8b2f-0e00c2afdd28" />

Utilizing the following command, the files were sucessfully checked in VirusTotal and MalwareBazaar and the findings were stored in the file with name test2.json
```
python3 IoC_analyzer.py -c config.json --input-file test2.txt --output test2.json
```
The following figures illustrate the results of the relevant examination.
<img width="1704" height="698" alt="image" src="https://github.com/user-attachments/assets/70a5df68-6310-4655-97aa-62994f4026bd" />
<img width="1701" height="671" alt="image" src="https://github.com/user-attachments/assets/afd99b47-123c-4f86-ae5b-091c1391eeff" />

## IP analysis
To analyze IPs, the following commands can be utilized, command to fetch IPs from a file is also contained.
```
python3 IoC_analyzer.py -c config.json 61.52.55.150
python3 IoC_analyzer.py -c config.json -t ip 61.52.55.150
python3 IoC_analyzer.py -c config.json --input-file testIP.txt --output testIP.json
```

## Domain Analysis
To analyze domains the following commands can be utilized, command to analyze domains from a file is also contained.
```
python3 IoC_analyzer.py -c config.json -t domain 19ak90ckxyjxc.life
python3 IoC_analyzer.py -c config.json 19ak90ckxyjxc.life
```




