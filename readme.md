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
   {
     "storeDirectory": "./files",

     "subject": {
       "email": {
         "prompt": "Email address for certificate administrator",
         "shortName": "E",
         "default": "something@example.com"
       },
       "organization": {
         "prompt": "Organization or Company Name",
         "shortName": "O",
         "default": "Example Home Lab Industries INC."
       },
       "locality": {
         "prompt": "City or Locality",
         "shortName": "L",
         "default": "New York"
       },
       "state": {
         "prompt": "State or Region",
         "shortName": "ST",
         "default": "New York"
       },
       "country": {
         "prompt": "Country code (eg. US)",
         "shortName": "C",
         "default": "US"
       }
     },

     "validDomains": [
       "example.com"
     ],

     "requireIntermediate": true,
     "defaultIntermediate": "intermediate",

     "validityLimits": {
       "minDays": 1,
       "maxDays": 397
     },

     "profileMetadata": {
       "webServer": { "validityDays": 90 },
       "ldapServer": { "validityDays": 30 }
     }
   }
   ```

3. Set a CA passphrase in your environment variables and run setup.

   - This passphrase is set once and is required for future requests.
   - This installs only production dependencies.

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

5. Submit a POST request to `http://localhost:{{SERVER.PORT}}/new` to issue a web server certificate

   ```json
   {
     "hostname": "certs.example.com",
     "altNames": [
       "certs.example.com",
       "certs.example.info",
       "localhost"
     ],
     "passphrase": "SecretPassphrase",
     "validityDays": 90
   }
   ```

   If `validityDays` is omitted, the server uses the profile default (when configured)
   or falls back to the standard one‑year lifetime. Requests outside the configured
   limits are rejected.

6. Submit a request to `http://localhost:{{SERVER.PORT}}/ldap` to generate an LDAP server certificate

   ```json
   {
     "hostname": "ldap.example.com",
     "altNames": [
       "ldap.example.com"
     ],
     "passphrase": "SecretPassphrase",
     "validityDays": 30
   }
   ```

7. Issued certificates are written to the directory specified by `storeDirectory`.

   - Leaf certificates: `newCerts/`
   - Private keys: `private/`
   - Root CA certificate: `certs/`

   If `"bundleP12": true` is included in the request body, a PKCS#12 bundle is also
   written to `newCerts/<hostname>.bundle.p12`.

8. (Optional) Create an intermediate CA by posting to
   `http://localhost:{{SERVER.PORT}}/intermediate` or running:

   ```cmd
   CAPASS=SecretPassphrase node scripts/setup-intermediate.js intermediate-name
   ```

   When `requireIntermediate` is `true`, the application refuses to issue leaf
   certificates directly from the root key. Issued certificates include a
   `.chain.crt` file containing both the leaf and intermediate certificates.

## Certificate lifetime policy

Leaf certificate lifetimes are configurable globally and per-profile. The server
enforces minimum and maximum validity limits, supports profile-specific defaults,
and allows clients to request a specific lifetime when issuing certificates.

CA and intermediate certificate lifetimes are controlled separately by setup
scripts and environment configuration and are not affected by request-level
settings.

## Audit logging

This project includes audit logging for privileged operations such as issuing
certificates, creating intermediates, and revoking certificates.

### What is logged

- Timestamp and operation type (create, revoke, intermediate, issue, etc.)
- Username/actor or source IP (when available)
- Target resource (hostname, intermediate name, certificate serial or fingerprint)
- Outcome (success or failure) and error details when applicable
- Certificate lifetime details (requested vs applied validity in days)
- Minimal request context required for traceability

Sensitive material such as private keys and passphrases is never logged.

### Configuration

- Audit events are emitted automatically during privileged operations.
- Audit entries are JSON objects (one per line) and include a timestamp.
- By default audit logs are written to stdout.
- To write audit logs to a file, set the `AUDIT_LOG_FILE` environment variable.
- Log rotation defaults to 1 MB per file with up to 5 retained files.

Application logs (`LOG_FILE`, `LOG_LEVEL`) are managed separately and do not affect
audit logging behavior.

### Example audit log entry

```json
{
  "ts": "2025-10-15T12:34:56.789Z",
  "level": "audit",
  "actor": "192.0.2.1",
  "operation": "issue_certificate",
  "target": "example.com",
  "result": "success",
  "serial": "01AB23CD",
  "details": {
    "altNames": ["example.com", "www.example.com"],
    "validityDaysRequested": 90,
    "validityDaysApplied": 90
  }
}
```

## Roadmap / Features

- Create intermediate CAs using the setup script or `/intermediate` endpoint
- Additional certificate profile customization
- Certificate expiration alerts
- Automatic renewal and delivery workflows
