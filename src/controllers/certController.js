const CSR = require('../resources/certificateRequest');
const CA = require('../resources/ca');

module.exports = {
  newWebServerCertificate: (hostname, passphrase, altNames = false) => {
    const csr = new CSR(hostname);
    if (altNames && altNames.length > 0) {
      csr.addAltNames(altNames);
    }
    csr.sign();
    if (!csr.verify()) {
      return {
        error: 'Unable to verify CSR'
      };
    }
    const ca = new CA();
    ca.unlockCA(passphrase);
    const certificate = ca.signCSR(csr);
    const privateKey = csr.getPrivateKey();
    return {
      certificate,
      privateKey,
      hostname
    };
  }
};
