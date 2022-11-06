# Dumptruck
A simple object-oriented C++ implementation to dump browser cookies and credentials from Chromium-based browsers such as Chrome and Edge. Supports the options to load the JSON object for further processing/exfiltration or dumps the JSON to disk. JSON data is represented in the following structure:
```
{
    "cookies": {
        "chrome": [
            {
               "hostkey": ".example.com",
               "name": "userid",
               "value": "fb43ed08-274e-4deb-8d23-427b6e273e1c"
            }
        ],   
        "msedge": [
            {
               "hostkey": ".example.com",
               "name": "sessionid",
               "value": "fb43ed08-274e-4deb-8d23-427b6e273e1c"
            }
        ]
    },
    "creds": {
        "chrome": [
            {
               "pass": "iLoooooveDumptruck.exe",
               "url": "http://example.com",
               "user": "JrM2628"
            }
        ],   
        "msedge": [
            {
               "pass": "$ecur3P455w0rd:p",
               "url": "http://192.168.1.1",
               "user": "admin"
            }
        ]
    }
}
```
### Note
TLDR: Using this will likely burn your red team engagement if deployed out-of-the-box. 

This tool was made for use in educational environments. The detection rate on [VirusTotal](https://www.virustotal.com/gui/file/cfbb8d48faa5e95f3c466cbf43ecdbe638e75140d1fbe451763452b70530020c) is 13/71 without any form of obfuscation, the binary is flagged for "suspicious behavior" on [AnyRun](https://app.any.run/tasks/d7a2223f-8c11-4516-a5f0-e892caefe258/), and it managed to generate a Threat Score of 100/100 on [Hybrid Analysis](https://www.hybrid-analysis.com/sample/cfbb8d48faa5e95f3c466cbf43ecdbe638e75140d1fbe451763452b70530020c). It is up to the user to provide AV evasion.  

### To Build
1. Install [vcpkg](https://vcpkg.io/en/getting-started.html) to manage sqlite3 and nlohmann-json dependencies 
2. Ensure [vcpkg.json](/chromedump/vcpkg.json) is in build directory
3. Build in Visual Studio as you usually would
