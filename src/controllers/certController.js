const CertificateRequest = require('../resources/certificateRequest');
const CA = require('../resources/ca');

module.exports = {
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
