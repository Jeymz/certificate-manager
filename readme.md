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
  - `LOG_FILE` - path to a log file
  - `LOG_LEVEL` - log level (default `info`)
  - `AUDIT_LOG_FILE` - path to the audit log file
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
   "requireIntermediate": true, // <- Prevents root from issuing leaf certs
   "defaultIntermediate": "intermediate", // <- Intermediate CA used for server certificates
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

6. Submit a request to `http://localhost:{{SERVER.PORT}}/ldap` to generate an LDAP server certificate

   ```json
   {
     "hostname": "ldap.example.com",
     "altNames": [
       "ldap.example.com"
     ],
     "passphrase": "SecretPassphrase"
   }
   ```

7. All your web certs will be saved to the directory specified in the config in the `newCerts` directory. Private keys are all in the `private` directory. Your Root CA cert is in the `certs` folder and will need to be applied to all machines as a Trusted Root Certificate. If `"bundleP12": true` is included in the request body, a PKCS#12 bundle will also be saved as `newCerts/<hostname>.bundle.p12`.
8. (Optional) Create an intermediate CA by posting to `http://localhost:{{SERVER.PORT}}/intermediate` or running:

   ```cmd
   CAPASS=SecretPassphrase node scripts/setup-intermediate.js intermediate-name
   ```

   This intermediate certificate will be placed under `files/intermediates/` and used by default for server certificates if `defaultIntermediate` is set in the configuration. When `requireIntermediate` is `true`, the application refuses to issue leaf certificates with the root key. When a server certificate is issued it is saved alongside a `.chain.crt` file containing both the server and intermediate certificates and the HTTP response includes this chain in a `chain` property. Present this chain so clients can validate the path using only the trusted root certificate.

## Audit logging

This project now includes audit logging for privileged operations (for example: issuing a new CA or intermediate, revoking certificates, and other actions that use the CA private key).

What is logged

- Timestamp and operation type (create, revoke, intermediate, etc.)
- Username/actor or source IP when available (depends on how you authenticate/forward requests)
- Target resource (hostname, intermediate name, certificate fingerprint or serial)
- Outcome (success or failure) and an error message when applicable
- Minimal context required to reproduce the action (request body fields such as hostname and altNames are recorded, but private key material and passphrases are never logged)

How to enable and configure

- The audit logger is wired into the application and audit calls are emitted by the application as part of privileged operations. Audit entries are emitted as JSON objects (one JSON object per line) and include a timestamp.
- By default audit entries are written to the console (stdout) in JSON format. To write audit entries to a dedicated file, set the `AUDIT_LOG_FILE` environment variable to a filesystem path.
- The audit logger uses a file transport (when `AUDIT_LOG_FILE` is set) with the following defaults: JSON format with a timestamp, maxsize = 1,048,576 bytes (1 MB) and maxFiles = 5 for simple rotation.
- Application logs (info/debug/error) are controlled separately by `LOG_FILE` and `LOG_LEVEL`. Setting `LOG_FILE` does not affect where audit logs are stored.

Environment variables (audit-related)

- `AUDIT_LOG_FILE` – path to the audit log file. When present audit entries are appended to this file (JSON, timestamped). If omitted, audit entries are written to stdout.
- `LOG_FILE` – path to the general application log file (separate from `AUDIT_LOG_FILE`).
- `LOG_LEVEL` – controls the general logger verbosity (default: `info`). Audit entries use a dedicated audit logger and are emitted regardless of `LOG_LEVEL`.

Example audit log entry (JSON, one line per entry)

```json
{"ts":"2025-10-15T12:34:56.789Z","level":"audit","actor":"192.0.2.1","operation":"issue_certificate","target":"example.com","result":"success","serial":"01AB23CD","details":{"altNames":["example.com","www.example.com"],"bundleP12":true}}
```

Notes and best practices

- Sensitive information: The implementation intentionally avoids logging sensitive secrets such as private keys and passphrases. Only operational metadata and request-level context are recorded.
- Rotation & retention: Use your system log rotation or a central log collector (ELK/Opensearch, Splunk, etc.) to rotate and retain audit logs according to your security policy.
- Time synchronization: Ensure your server's clock is synchronized (NTP) so timestamps can be correlated across systems.
- Forwarding logs: If you forward logs to a central collector, make sure transport and storage are protected (TLS, access controls).

## Roadmap / Features

- Create intermediate CAs using the setup script or `/intermediate` endpoint
- Allow more customization regarding certificate types and subjects
- Alert administrator when certificate is about to expire
- Enable admins to auto issue new certificates and send them to the certificate administrator
