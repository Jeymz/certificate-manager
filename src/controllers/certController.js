const fs = require('fs').promises;
const path = require('path');
const CertificateRequest = require('../resources/certificateRequest');
const CA = require('../resources/ca');
const config = require('../resources/config')();

module.exports = {
  /**
   * Generate and sign a new web server certificate.
   *
   * @param {string} hostname - Fully qualified domain name for the certificate.
   * @param {string} passphrase - Passphrase to unlock the CA key.
   * @param {string[]|false} [altNames=false] - Optional alternative names.
   * @returns {Promise<Object>} Resolves with certificate and key PEM strings.
   */
  newWebServerCertificate: async(hostname, passphrase, altNames = false) => {
    const csr = new CertificateRequest(hostname);
    if (altNames && altNames.length > 0) {
      csr.addAltNames(altNames);
    }
    csr.sign();
    if (!csr.verify()) {
      return {
        error: 'Unable to verify CSR',
      };
    }
    const ca = await new CA(config.getDefaultIntermediate());
    ca.unlockCA(passphrase);
    const certificate = await ca.signCSR(csr);
    const caCert = ca.getCACertificate();
    const privateKey = csr.getPrivateKey();
    const chain = `${certificate}${caCert}`;
    return {
      certificate,
      privateKey,
      hostname,
      chain,
    };
  },

  /**
   * Generate and sign a new intermediate CA certificate.
   *
   * @param {string} hostname - Name for the intermediate CA.
   * @param {string} passphrase - Passphrase to unlock the root CA key.
   * @returns {Promise<Object>} Resolves with certificate and key PEM strings.
   */
  newIntermediateCA: async(hostname, passphrase) => {
    const csr = new CertificateRequest(hostname);
    csr.setCertType('intermediateCA');
    csr.sign();
    if (!csr.verify()) {
      return { error: 'Unable to verify CSR' };
    }
    const ca = await new CA();
    ca.unlockCA(passphrase);
    const certificate = await ca.signCSR(csr);
    const privateKey = csr.getPrivateKey();
    const intDir = path.join(config.getStoreDirectory(), 'intermediates');
    await fs.mkdir(intDir, { recursive: true });
    await fs.writeFile(path.join(intDir, `${hostname}.cert.crt`), certificate, { encoding: 'utf-8' });
    await fs.writeFile(path.join(intDir, `${hostname}.key.pem`), privateKey, { encoding: 'utf-8' });
    return { certificate, privateKey, hostname };
  },
};
