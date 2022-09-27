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
               "hostkey": ".example.com",
               "name": "userid",
               "value": "fb43ed08-274e-4deb-8d23-427b6e273e1c"
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

### To Build
1. Install [vcpkg](https://vcpkg.io/en/getting-started.html) to manage sqlite3 and nlohmann-json dependencies 
2. Ensure [vcpkg.json](vcpkg.json) is in build directory
3. Build in Visual Studio as you usually would
