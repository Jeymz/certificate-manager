const CertificateRequest = require('../resources/certificateRequest');
const CA = require('../resources/ca');

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
    const ca = await new CA();
    ca.unlockCA(passphrase);
    const certificate = await ca.signCSR(csr);
    const privateKey = csr.getPrivateKey();
    return {
      certificate,
      privateKey,
      hostname,
    };
  },
};
