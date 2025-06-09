# Certificate Manager

## Warnings

This is a work in progress. Use at your own risk.

## Setup

The project can be used either as a stand‑alone tool or as a development
dependency. Installation differs slightly for each case.

### For Users

- Install [Node.js](https://nodejs.org/) **v22** or later
- Set the `CAPASS` environment variable before running the setup script
- (Optional) environment variables:
  - `CA_VALIDITY_YEARS` – number of years the root CA is valid (default `5`)
  - `LOG_FILE` – path to a log file
  - `LOG_LEVEL` – log level (default `info`)
- Install runtime dependencies with `npm install --production`
- Run `npm run setup` to generate the root CA
- Start the server with `npm start`

### For Contributors

- Install all dependencies with `npm install` (or `npm ci`)
- Run `npm run lint` to lint the codebase
- Execute tests with `npm test`
- Start the development server with `npm run dev`
- On Windows you can use `npm run win` instead

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
   npm start
   ```

   For development use:

   ```cmd
   npm run dev
   ```

   Windows users can run `npm run win` for development on Windows.

5. Submit a post request to the `http://localhost:{{SERVER.PORT}}/new` endpoint with the following json body

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
- Enable admins to auto issue new certificates and send them to the certificate administrator
