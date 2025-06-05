# Certificate Manager

## Warnings
This is a work in progress. Use at your own risk.

## Example
1. Copy the configuration example
```cmd
cp config\defaults.example.json config\defaults.json
```
2. Edit the configuration to best fit your needs
```json
...
"storeDirectory": "./files", // <- This is where your CA and certs will be saved
  "subject": {
    "email": {
      "prompt": "Email address for certificate administrator",
      "shortName": "E",
      "default": "something@example.com" // <- Email displayed on certificates
    },
    "organization": {
      "prompt": "Organization or Company Name",
      "shortName": "O",
      "default": "Example Home Lab Industries INC."  // <- Organization or Company Name
    },
    "locality": {
      "prompt": "City or Locality",
      "shortName": "L",
      "default": "New York" // <- City or Locality
    },
    "state": {
      "prompt": "State or Region",
      "shortName": "ST",
      "default": "New York" // <- State or Province
    },
    "country": {
      "prompt": "Country code (eg. US)",
      "shortName": "C",
      "default": "US" // <- 2 character Country Code
    }
  },
  "validDomains": [
    "example.com" // <- This is used to validate cert request hostnames not alternate names
  ],
  ...
```
3. Set a CA passphrase in your environment variables and run setup.
- Note: This passphrase only be set once and will be needed to submit future requests
- Note: This will install only production needed dependencies
```cmd
SET CAPASS=SecretPassphrase && npm run setup
```
4. Run the server
```cmd
npm run win
```
5. Submit a post request to the http://localhost:`port`/new endpoint with the following json body
```json
{
  "hostname": "certs.example.com",
  "altNames": [
    "certs.example.com",
    "certs.example.info",
    "localhost"
  ],
  "passphrase": "SecretPassphrase"
}
```
6. All your web certs will be saved to the directory specified in the config in the `newCerts` directory. Private keys are all in the `private` directory. Your Root CA cert is in the `certs` folder and will need to be applied to all machines as a Trusted Root Certificate

## Roadmap / Features
- Allow for creating intermediate CAs
- Allow more customization regarding certificate types and subjects
- Alert administrator when certificate is about to expire
- Enable admins to auto issue new certificates and send to certificate administrator