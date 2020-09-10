# Namecheap CLI

Currently WIP. Did this in a few hours to accomdate a personal requirement on SSL certificates.. Please feel free to build on this.

## Requirements

Developed this CLI using Python 3.8.3.. Execute the following command to install the required packages.

```bash
pip3 install -r requirements.txt
```

## Modules Supported

### SSL

Currently only a few functions are available

#### List SSL Certificates
```bash
python3 namecheap.py ssl --method list
```

#### Create SSL Certificate

Currently only wildcard and DNS verification is supported, will be adding more in the future.

```bash
python3 namecheap.py ssl --type wildcard
```

#### Activating/Reissue SSL Certificates

Activation and Reissue of SSL Certificate.

The outputfile flag is useful to combine this script with another DNS cli tool for auto DNS CNAME verification. 

```bash
python3 namecheap.py ssl --method activate --csr <csr file path> --email "<email address>" --certid <cert id> --issuetype <activate/reissue> --outputfile <bool>
```


