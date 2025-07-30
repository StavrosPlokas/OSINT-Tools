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

For the test a configuration file was utilized that contained the relevant API keys.

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
To analyze IPs, the following commands can be utilized, command to fetch IPs from a file and output it in a target file is also contained.
```
python3 IoC_analyzer.py -c config.json 61.52.55.150
python3 IoC_analyzer.py -c config.json -t ip 61.52.55.150
python3 IoC_analyzer.py -c config.json --input-file testIP.txt --output testIP.json
```

## Domain Analysis
To analyze domains the following commands can be utilized, command to analyze domains from a file and output it in a target file is also contained.
```
python3 IoC_analyzer.py -c config.json -t domain 19ak90ckxyjxc.life
python3 IoC_analyzer.py -c config.json 19ak90ckxyjxc.life
python3 IoC_analyzer.py -c config.json --input-file testdomain.txt --output testdomai.json
```

## URL analysis
To analyze domains the following commands can be utilized, command to analyze domains from a file and output it in a target file is also contained.
```
python3 IoC_analyzer.py -c config.json http://217.156.122.82/hiddenbin/boatnet.arm7
python3 IoC_analyzer.py -c config.json -t url http://217.156.122.82/hiddenbin/boatnet.arm7
python3 IoC_analyzer.py -c config.json --input-file testurl.txt  --output testurl.json
```
## Autodetect POC
Finally, one of the most helpful utilities is to have various IoCs in a file and recognize each one to perform the analysis utilizing the relevant platforms.
For this exercise the following IoCs utilized.
```
http://217.156.122.82/hiddenbin/boatnet.arm7 //URL
arearugs.top //DOMAIN
0a09f94c33ebd57d817260b6899bb70b27473ce8661626f13b4d66c931213fca // SHA256 HASH
61.53.127.74 //IP
56c0c0627976d40963e4d879ce22562d // MD5 HASH
```
The command that was utilized in the following
```
python3 IoC_analyzer.py -c config.json --input-file testfinal.txt  --output testfinal.json
```
The output of the analysis was the following
```json
{
  "metadata": {
    "ioc_count": 1,
    "timestamp": "2025-07-30T05:22:10.754754",
    "types_analyzed": [
      "hash"
    ],
    "verdicts": {
      "found": 2,
      "not_found": 0,
      "errors": 0
    }
  },
  "results": [
    {
      "input_value": "7c59ac829ee7bdd43413539d2a8a6a968d2fb35fe56b935b5f0a4baef8dcdb25",
      "input_type": "hash",
      "analysis_timestamp": "2025-07-30T05:22:09.245171",
      "results": {
        "virustotal": {
          "service": "VirusTotal",
          "status": "found",
          "timestamp": "2025-07-30T05:22:10.015471",
          "url": "https://www.virustotal.com/gui/file/7c59ac829ee7bdd43413539d2a8a6a968d2fb35fe56b935b5f0a4baef8dcdb25/detection/f-7c59ac829ee7bdd43413539d2a8a6a968d2fb35fe56b935b5f0a4baef8dcdb25-1753857115",
          "error": null,
          "detections": 53,
          "total_engines": 72,
          "scan_date": "2025-07-30 06:31:55",
          "positives": [
            "ALYac",
            "APEX",
            "AVG",
            "Acronis",
            "AhnLab-V3",
            "Alibaba",
            "Antiy-AVL",
            "Arcabit",
            "Avast",
            "Avira",
            "Baidu",
            "BitDefender",
            "Bkav",
            "CAT-QuickHeal",
            "CMC",
            "CTX",
            "ClamAV",
            "CrowdStrike",
            "Cylance",
            "Cynet",
            "DeepInstinct",
            "DrWeb",
            "ESET-NOD32",
            "Elastic",
            "Emsisoft",
            "F-Secure",
            "Fortinet",
            "GData",
            "Google",
            "Gridinsoft",
            "Ikarus",
            "Jiangmin",
            "K7AntiVirus",
            "K7GW",
            "Kaspersky",
            "Kingsoft",
            "Lionic",
            "Malwarebytes",
            "MaxSecure",
            "McAfeeD",
            "MicroWorld-eScan",
            "Microsoft",
            "NANO-Antivirus",
            "Paloalto",
            "Panda",
            "Rising",
            "SUPERAntiSpyware",
            "Sangfor",
            "SentinelOne",
            "Skyhigh",
            "Sophos",
            "Symantec",
            "TACHYON",
            "Tencent",
            "Trapmine",
            "TrellixENS",
            "TrendMicro",
            "TrendMicro-HouseCall",
            "VBA32",
            "VIPRE",
            "Varist",
            "ViRobot",
            "VirIT",
            "Webroot",
            "Xcitium",
            "Yandex",
            "Zillya",
            "ZoneAlarm",
            "Zoner",
            "alibabacloud",
            "huorong",
            "tehtris"
          ]
        },
        "malware_bazaar": {
          "service": "Malware Bazaar",
          "status": "found",
          "timestamp": "2025-07-30T05:22:10.754275",
          "url": "https://bazaar.abuse.ch/sample/7c59ac829ee7bdd43413539d2a8a6a968d2fb35fe56b935b5f0a4baef8dcdb25",
          "error": null,
          "family": "CobaltStrike",
          "tags": [
            "CobaltStrike",
            "exe"
          ],
          "file_type": "exe",
          "signature": "CobaltStrike"
        },
        "hybrid_analysis": {
          "service": "Hybrid Analysis",
          "status": "no_api_key",
          "timestamp": "2025-07-30T05:22:10.754322",
          "url": "https://www.hybrid-analysis.com/sample/7c59ac829ee7bdd43413539d2a8a6a968d2fb35fe56b935b5f0a4baef8dcdb25",
          "error": "API key not provided"
        },
        "anyrun": {
          "service": "Any.run",
          "status": "no_api_key",
          "timestamp": "2025-07-30T05:22:10.754328",
          "url": "https://app.any.run/tasks/?hash=7c59ac829ee7bdd43413539d2a8a6a968d2fb35fe56b935b5f0a4baef8dcdb25",
          "error": "API key not provided"
        }
      }
    }
  ]
}
test@plokasslap:/mnt/c/Users/plokas/Desktop/tools$
test@plokasslap:/mnt/c/Users/plokas/Desktop/tools$
test@plokasslap:/mnt/c/Users/plokas/Desktop/tools$
test@plokasslap:/mnt/c/Users/plokas/Desktop/tools$ ls
 7c59ac829ee7bdd43413539d2a8a6a968d2fb35fe56b935b5f0a4baef8dcdb25.json   CyberChef_v10.19.4.zip          Nirsoft            TIv3.py                                         testfinal.json
'AV Remove Exlusions'                                                    MobaXterm_Installer_v25.2       Opera_Broser.ps1   analysis_results.json
 CyberChef_v10.19.4                                                      MobaXterm_Installer_v25.2.zip   Opera_Local.ps1    burpsuite_community_windows-x64_v2025_3_3.exe
test@plokasslap:/mnt/c/Users/plokas/Desktop/tools$ cat testfinal.json | jq '.'
{
  "metadata": {
    "ioc_count": 5,
    "timestamp": "2025-07-30T06:13:37.319726",
    "types_analyzed": [
      "domain",
      "ip",
      "url",
      "hash"
    ],
    "verdicts": {
      "found": 6,
      "not_found": 0,
      "errors": 2
    }
  },
  "results": [
    {
      "input_value": "http://217.156.122.82/hiddenbin/boatnet.arm7",
      "input_type": "url",
      "analysis_timestamp": "2025-07-30T06:13:19.651704",
      "results": {
        "urlhaus": {
          "service": "URLHaus",
          "status": "found",
          "timestamp": "2025-07-30T06:13:20.404706",
          "url": "https://urlhaus.abuse.ch/url/3592852",
          "error": null,
          "url_id": "3592852",
          "date_added": "2025-07-29 21:01:06 UTC",
          "host": "217.156.122.82",
          "tags": [
            "32-bit",
            "elf",
            "mirai",
            "Mozi"
          ],
          "payloads": [
            {
              "sha256": "611f61a5a4584b968c397f9bb542b52bc15c3c6c80490f76c898f962da5b8b18",
              "file_type": "elf",
              "file_size": "46624",
              "first_seen": "2025-07-29"
            }
          ],
          "threat_status": "malware_download"
        },
        "virustotal": {
          "service": "VirusTotal",
          "status": "found",
          "timestamp": "2025-07-30T06:13:20.874972",
          "url": "https://www.virustotal.com/gui/url/08a2d0b112d63294ee26cf9d0511b082e0e59f1a20c6b0d4a7e436d9e79eae20/detection/u-08a2d0b112d63294ee26cf9d0511b082e0e59f1a20c6b0d4a7e436d9e79eae20-1753869543",
          "error": null,
          "detections": 12,
          "total_engines": 97,
          "scan_date": "2025-07-30 09:59:03",
          "positives": [
            "AILabs (MONITORAPP)",
            "BitDefender",
            "ESET",
            "Emsisoft",
            "Forcepoint ThreatSeeker",
            "Fortinet",
            "G-Data",
            "Kaspersky",
            "Quick Heal",
            "SOCRadar",
            "URLhaus",
            "VIPRE"
          ]
        }
      }
    },
    {
      "input_value": "arearugs.top",
      "input_type": "domain",
      "analysis_timestamp": "2025-07-30T06:13:20.876329",
      "results": {
        "virustotal": {
          "service": "VirusTotal",
          "status": "analyzed",
          "timestamp": "2025-07-30T06:13:24.690196",
          "url": "https://www.virustotal.com/gui/domain/arearugs.top",
          "error": null,
          "registrar": "PDR Ltd",
          "creation_date": "2025-07-29T11:57:20+00:00",
          "expiration_date": null,
          "name_servers": null,
          "categories": {
            "alphaMountain.ai": "Malicious (alphaMountain.ai)"
          },
          "subdomains_count": null,
          "last_analysis_stats": {
            "malicious": 12,
            "suspicious": 0,
            "undetected": 29,
            "harmless": 53,
            "timeout": 0
          },
          "last_analysis_results": null
        },
        "securitytrails": {
          "service": "SecurityTrails",
          "status": "error",
          "timestamp": "2025-07-30T06:13:24.690313",
          "url": null,
          "error": "SecurityTrails API key not provided"
        }
      }
    },
    {
      "input_value": "0a09f94c33ebd57d817260b6899bb70b27473ce8661626f13b4d66c931213fca",
      "input_type": "hash",
      "analysis_timestamp": "2025-07-30T06:13:24.690674",
      "results": {
        "virustotal": {
          "service": "VirusTotal",
          "status": "found",
          "timestamp": "2025-07-30T06:13:28.660437",
          "url": "https://www.virustotal.com/gui/file/0a09f94c33ebd57d817260b6899bb70b27473ce8661626f13b4d66c931213fca/detection/f-0a09f94c33ebd57d817260b6899bb70b27473ce8661626f13b4d66c931213fca-1753865470",
          "error": null,
          "detections": 31,
          "total_engines": 69,
          "scan_date": "2025-07-30 08:51:10",
          "positives": [
            "ALYac",
            "APEX",
            "Acronis",
            "AhnLab-V3",
            "Alibaba",
            "Antiy-AVL",
            "Arcabit",
            "Avira",
            "BitDefender",
            "Bkav",
            "CAT-QuickHeal",
            "CMC",
            "CTX",
            "ClamAV",
            "CrowdStrike",
            "Cylance",
            "Cynet",
            "DeepInstinct",
            "DrWeb",
            "ESET-NOD32",
            "Elastic",
            "Emsisoft",
            "F-Secure",
            "Fortinet",
            "GData",
            "Google",
            "Gridinsoft",
            "Ikarus",
            "Jiangmin",
            "K7AntiVirus",
            "K7GW",
            "Kaspersky",
            "Kingsoft",
            "Lionic",
            "Malwarebytes",
            "MaxSecure",
            "McAfeeD",
            "MicroWorld-eScan",
            "Microsoft",
            "NANO-Antivirus",
            "Paloalto",
            "Panda",
            "Rising",
            "SUPERAntiSpyware",
            "Sangfor",
            "SentinelOne",
            "Skyhigh",
            "Sophos",
            "Symantec",
            "TACHYON",
            "Tencent",
            "Trapmine",
            "TrellixENS",
            "TrendMicro",
            "TrendMicro-HouseCall",
            "VBA32",
            "VIPRE",
            "Varist",
            "ViRobot",
            "VirIT",
            "Webroot",
            "Xcitium",
            "Yandex",
            "Zillya",
            "ZoneAlarm",
            "Zoner",
            "alibabacloud",
            "huorong",
            "tehtris"
          ]
        },
        "malware_bazaar": {
          "service": "Malware Bazaar",
          "status": "found",
          "timestamp": "2025-07-30T06:13:29.312110",
          "url": "https://bazaar.abuse.ch/sample/0a09f94c33ebd57d817260b6899bb70b27473ce8661626f13b4d66c931213fca",
          "error": null,
          "family": "XWorm",
          "tags": [
            "exe",
            "XWorm"
          ],
          "file_type": "exe",
          "signature": "XWorm"
        },
        "hybrid_analysis": {
          "service": "Hybrid Analysis",
          "status": "no_api_key",
          "timestamp": "2025-07-30T06:13:29.312214",
          "url": "https://www.hybrid-analysis.com/sample/0a09f94c33ebd57d817260b6899bb70b27473ce8661626f13b4d66c931213fca",
          "error": "API key not provided"
        },
        "anyrun": {
          "service": "Any.run",
          "status": "no_api_key",
          "timestamp": "2025-07-30T06:13:29.312228",
          "url": "https://app.any.run/tasks/?hash=0a09f94c33ebd57d817260b6899bb70b27473ce8661626f13b4d66c931213fca",
          "error": "API key not provided"
        }
      }
    },
    {
      "input_value": "61.53.127.74",
      "input_type": "ip",
      "analysis_timestamp": "2025-07-30T06:13:29.313264",
      "results": {
        "virustotal": {
          "service": "VirusTotal",
          "status": "analyzed",
          "timestamp": "2025-07-30T06:13:32.689723",
          "url": "https://www.virustotal.com/gui/ip-address/61.53.127.74",
          "error": null,
          "country": "CN",
          "city": null,
          "isp": null,
          "reputation_score": 0,
          "abuse_confidence": null,
          "open_ports": null
        },
        "abuseipdb": {
          "service": "AbuseIPDB",
          "status": "analyzed",
          "timestamp": "2025-07-30T06:13:33.126867",
          "url": "https://www.abuseipdb.com/check/61.53.127.74",
          "error": null,
          "country": "CN",
          "city": null,
          "isp": "China Unicom Henan province network",
          "reputation_score": null,
          "abuse_confidence": 0,
          "open_ports": null
        },
        "shodan": {
          "service": "Shodan",
          "status": "error",
          "timestamp": "2025-07-30T06:13:33.253430",
          "url": null,
          "error": "404 Client Error: Not Found for url: https://api.shodan.io/shodan/host/61.53.127.74?key=cGve62hhzHi9T3nYkpUxvfZfPBx72gB6"
        },
        "geolocation": {
          "service": "IP Geolocation",
          "status": "analyzed",
          "timestamp": "2025-07-30T06:13:33.383401",
          "url": null,
          "error": null,
          "country": "China",
          "city": "Zhengzhou",
          "isp": "CNC Group CHINA169 Henan Province Network",
          "reputation_score": null,
          "abuse_confidence": null,
          "open_ports": null
        }
      }
    },
    {
      "input_value": "56c0c0627976d40963e4d879ce22562d",
      "input_type": "hash",
      "analysis_timestamp": "2025-07-30T06:13:33.384141",
      "results": {
        "virustotal": {
          "service": "VirusTotal",
          "status": "found",
          "timestamp": "2025-07-30T06:13:36.634462",
          "url": "https://www.virustotal.com/gui/file/29e2c62354cb70c259ee016b3acfcece6cb82c394bd64af43bd35b42f3989053/detection/f-29e2c62354cb70c259ee016b3acfcece6cb82c394bd64af43bd35b42f3989053-1753867510",
          "error": null,
          "detections": 18,
          "total_engines": 72,
          "scan_date": "2025-07-30 09:25:10",
          "positives": [
            "ALYac",
            "APEX",
            "AVG",
            "Acronis",
            "AhnLab-V3",
            "Alibaba",
            "Antiy-AVL",
            "Arcabit",
            "Avast",
            "Avira",
            "Baidu",
            "BitDefender",
            "Bkav",
            "CAT-QuickHeal",
            "CMC",
            "CTX",
            "ClamAV",
            "CrowdStrike",
            "Cylance",
            "Cynet",
            "DeepInstinct",
            "DrWeb",
            "ESET-NOD32",
            "Elastic",
            "Emsisoft",
            "F-Secure",
            "Fortinet",
            "GData",
            "Google",
            "Gridinsoft",
            "Ikarus",
            "Jiangmin",
            "K7AntiVirus",
            "K7GW",
            "Kaspersky",
            "Kingsoft",
            "Lionic",
            "Malwarebytes",
            "MaxSecure",
            "McAfeeD",
            "MicroWorld-eScan",
            "Microsoft",
            "NANO-Antivirus",
            "Paloalto",
            "Panda",
            "Rising",
            "SUPERAntiSpyware",
            "Sangfor",
            "SentinelOne",
            "Skyhigh",
            "Sophos",
            "Symantec",
            "TACHYON",
            "Tencent",
            "Trapmine",
            "TrellixENS",
            "TrendMicro",
            "TrendMicro-HouseCall",
            "VBA32",
            "VIPRE",
            "Varist",
            "ViRobot",
            "VirIT",
            "Webroot",
            "Xcitium",
            "Yandex",
            "Zillya",
            "ZoneAlarm",
            "Zoner",
            "alibabacloud",
            "huorong",
            "tehtris"
          ]
        },
        "malware_bazaar": {
          "service": "Malware Bazaar",
          "status": "found",
          "timestamp": "2025-07-30T06:13:37.318459",
          "url": "https://bazaar.abuse.ch/sample/56c0c0627976d40963e4d879ce22562d",
          "error": null,
          "family": "AgentTesla",
          "tags": [
            "AgentTesla",
            "exe",
            "signed"
          ],
          "file_type": "exe",
          "signature": "AgentTesla"
        },
        "hybrid_analysis": {
          "service": "Hybrid Analysis",
          "status": "no_api_key",
          "timestamp": "2025-07-30T06:13:37.318556",
          "url": "https://www.hybrid-analysis.com/sample/56c0c0627976d40963e4d879ce22562d",
          "error": "API key not provided"
        },
        "anyrun": {
          "service": "Any.run",
          "status": "no_api_key",
          "timestamp": "2025-07-30T06:13:37.318568",
          "url": "https://app.any.run/tasks/?hash=56c0c0627976d40963e4d879ce22562d",
          "error": "API key not provided"
        }
      }
    }
  ]
}
```





