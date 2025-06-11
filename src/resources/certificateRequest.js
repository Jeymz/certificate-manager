const crypto = require('crypto');
const net = require('net');
const forge = require('node-forge');
const config = require('./config')();

/**
 * Helper for generating certificate signing requests.
 */
module.exports = class CertificateRequest {
  #private = {};

  /**
   * Create a certificate request for the given hostname.
   *
   * @param {string} hostname - Fully qualified domain name for the CSR.
   * @throws {Error} When the hostname fails validation.
   */
  constructor(hostname, keypair = null) {
    let keys;
    if (keypair && keypair.publicKey && keypair.privateKeyPEM) {
      let privateKey;
      if (keypair.passphrase) {
        privateKey = forge.pki.decryptRsaPrivateKey(
          keypair.privateKeyPEM,
          keypair.passphrase,
        );
        if (!privateKey) {
          try {
            const info = forge.pki.decryptPrivateKeyInfo(
              forge.pki.encryptedPrivateKeyFromPem(keypair.privateKeyPEM),
              keypair.passphrase,
            );
            privateKey = forge.pki.privateKeyFromAsn1(info);
          } catch (err) {
            privateKey = null;
          }
        }
      } else {
        try {
          privateKey = forge.pki.privateKeyFromPem(keypair.privateKeyPEM);
        } catch (err) {
          privateKey = null;
        }
      }
      keys = {
        publicKey: keypair.publicKey,
        privateKey,
        privateKeyPEM: keypair.privateKeyPEM,
      };
    } else {
      const generated = forge.pki.rsa.generateKeyPair(2048);
      keys = {
        publicKey: forge.pki.publicKeyToPem(generated.publicKey),
        privateKey: generated.privateKey,
        privateKeyPEM: forge.pki.privateKeyToPem(generated.privateKey),
      };
    }
    this.#private.keypair = keys;
    this.#private.csr = forge.pki.createCertificationRequest();
    this.#private.csr.publicKey = forge.pki.publicKeyFromPem(this.#private.keypair.publicKey);
    const subject = config.getSubject();
    this.#private.validator = config.getValidator();
    const normalized = hostname.toString().toLowerCase();
    if (!this.#private.validator.hostname(normalized)) {
      throw new Error(`Invalid hostname: ${hostname}`);
    }
    subject.push({
      shortName: 'CN',
      value: normalized,
    });
    this.#private.csr.setSubject(subject);
    this.#private.attributes = [
      {
        name: 'challengePassword',
        value: crypto.randomBytes(32).toString('base64'),
      },
      {
        name: 'unstructuredName',
        value: 'Robotti Tech Services',
      },
    ];
    this.#private.hostname = normalized;
    this.#private.certType = 'webServer';
  }

  /**
   * Add subject alternative names to the certificate request.
   *
   * @param {string[]} altNames - IP addresses or hostnames to include.
   * @returns {void}
   */
  addAltNames(altNames) {
    const subjectAltName = {
      name: 'subjectAltName',
      altNames: [],
    };
    altNames.forEach((alternateName) => {
      const normalized = alternateName.toString().toLowerCase();
      if (net.isIP(normalized)) {
        subjectAltName.altNames.push({
          type: 7,
          ip: normalized,
        });
      } else if (this.#private.validator.hostname(normalized)) {
        subjectAltName.altNames.push({
          type: 2,
          value: normalized,
        });
      }
    });
    if (subjectAltName.altNames.length > 0) {
      this.#private.attributes.push({
        name: 'extensionRequest',
        extensions: [
          subjectAltName,
        ],
      });
    }
  }

  /**
   * Finalize the certificate request and produce a PEM encoded CSR.
   *
   * @returns {void}
   */
  sign() {
    this.#private.csr.setAttributes(this.#private.attributes);
    this.#private.csr.sign(this.#private.keypair.privateKey);
    this.#private.csrPEM = forge.pki.certificationRequestToPem(this.#private.csr);
  }

  /**
   * Validate that the generated CSR is correctly signed.
   *
   * @returns {boolean} True if the CSR's signature is valid.
   */
  verify() {
    return this.#private.csr.verify();
  }

  /**
   * Retrieve the primary hostname for this request.
   *
   * @returns {string} Hostname tied to the CSR.
   */
  getHostname() {
    return this.#private.hostname;
  }

  /**
   * Get the PEM encoded certificate signing request.
   *
   * @returns {string} PEM formatted CSR.
   */
  getCSR() {
    return this.#private.csrPEM;
  }

  /**
   * Return the generated private key in PEM format.
   *
   * @returns {string} PEM encoded private key.
   */
  getPrivateKey() {
    return this.#private.keypair.privateKeyPEM
      || forge.pki.privateKeyToPem(this.#private.keypair.privateKey);
  }

  /**
   * Specify the certificate type used when signing the CSR.
   *
   * @param {string} certType - Key for a configured certificate profile.
   * @throws {Error} When an invalid type is provided.
   * @returns {void}
   */
  setCertType(certType) {
    const certConfigs = config.getCertExtensions();
    if (Object.keys(certConfigs).indexOf(certType.toString()) < 0) {
      throw new Error(`Unsupported certificate type '${certType}'. Supported types: ${Object.keys(certConfigs).join(', ')}`);
    } else {
      this.#private.certType = certType.toString();
    }
  }

  /**
   * Get the configured certificate type for this request.
   *
   * @returns {string} Current certificate type.
   */
  getCertType() {
    return this.#private.certType;
  }

  /**
   * Generate a PKCS#12 bundle for the provided certificate and chain.
   *
   * @param {string} certificate - Leaf certificate in PEM format.
   * @param {string} chain - PEM encoded certificate chain.
   * @param {string} password - Encryption password for the bundle.
   * @returns {string} Base64 encoded PKCS#12 archive.
   */
  getPkcs12Bundle(certificate, chain, password) {
    if (!password || password.length < 4) {
      throw new Error('Password required for PKCS#12 export (minimum 4 characters)');
    }
    const leaf = forge.pki.certificateFromPem(certificate);
    const caCerts = [];
    if (chain) {
      const blocks = forge.pem.decode(chain);
      blocks.forEach((block) => {
        if (block.type === 'CERTIFICATE') {
          caCerts.push(forge.pki.certificateFromPem(forge.pem.encode(block)));
        }
      });
    }
    const pkcs12Asn1 = forge.pkcs12.toPkcs12Asn1(
      this.#private.keypair.privateKey,
      leaf,
      password,
      { algorithm: 'aes256', usePBKDF2: true, ca: caCerts },
    );
    const der = forge.asn1.toDer(pkcs12Asn1).getBytes();
    return Buffer.from(der, 'binary').toString('base64');
  }
};
