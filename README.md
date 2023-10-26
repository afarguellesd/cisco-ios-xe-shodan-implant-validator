# Cisco IOS XE valitador with Shodan

This is a sample script to check for compromised hosts based on Shodan search results

# Requirements

* Python 3.10+
* A Shodan API key

# Instructions

1. Install the dependencies found in the `requirements.txt` file.
    ```
    pip install -r requirements.txt
    ```
2. Run the help of the script to check required arguments
    ```
    python cisco_validator.py -h
    ```
3. Build your command line based on your needs

# References

- [Bleeping Commputer | Hackers update Cisco IOS XE backdoor to hide infected devices](https://www.bleepingcomputer.com/news/security/hackers-update-cisco-ios-xe-backdoor-to-hide-infected-devices/)
- [Fox IT | Cisco IOS XE implant scanning](https://github.com/fox-it/cisco-ios-xe-implant-detection/tree/main)