const revocation = require('../resources/revocation');
const certService = require('../services/certService');
const crlService = require('../services/crlService');

module.exports = {
  /**
   * Generate and sign a new web server certificate.
   *
   * @param {string} hostname - Fully qualified domain name for the certificate.
   * @param {string} passphrase - Passphrase to unlock the CA key.
   * @param {string[]|false} [altNames=false] - Optional alternative names.
   * @param {boolean} [bundleP12=false] - Whether to bundle as PKCS#12.
   * @param {string|null} [password=null] - Optional bundle password.
   * @returns {Promise<Object>} Resolves with certificate and key PEM strings.
   */
  newWebServerCertificate: async(hostname, passphrase, altNames = false, bundleP12 = false, password = null, validityDays = null, performedBy = undefined) => {
    return await certService.newWebServerCertificate(hostname, passphrase, altNames, bundleP12, password, validityDays, performedBy);
  },
  
  /**
   * Generate and sign a new LDAP server certificate.
   *
   * @param {string} hostname - Fully qualified domain name for the certificate.
   * @param {string} passphrase - Passphrase to unlock the CA key.
   * @param {string[]|false} [altNames=false] - Optional alternative names.
   * @param {boolean} [bundleP12=false] - Whether to bundle as PKCS#12.
   * @param {string|null} [password=null] - Optional bundle password.
   * @returns {Promise<Object>} Resolves with certificate and key PEM strings.
   */
  newLdapServerCertificate: async(hostname, passphrase, altNames = false, bundleP12 = false, password = null, validityDays = null, performedBy = undefined) => {
    return await certService.newLdapServerCertificate(hostname, passphrase, altNames, bundleP12, password, validityDays, performedBy);
  },

  /**
   * Renew an existing certificate using its serial number.
   *
   * @param {string} serialNumber - Serial number of the certificate to renew.
   * @param {string} passphrase - Passphrase to unlock the CA key.
   * @returns {Promise<Object>} Resolves with renewed certificate material.
   */
  renewCertificate: async(serialNumber, passphrase, bundleP12 = false, password = null, validityDays = null, performedBy = undefined) => {
    return await certService.renewCertificate(serialNumber, passphrase, bundleP12, password, validityDays, performedBy);
  },

  /**
   * Generate and sign a new intermediate CA certificate.
   *
   * @param {string} hostname - Name for the intermediate CA.
   * @param {string} passphrase - Passphrase to unlock the root CA key.
   * @returns {Promise<Object>} Resolves with certificate and key PEM strings.
   */
  newIntermediateCA: async(hostname, passphrase, intermediatePassphrase, performedBy = undefined) => {
    return await certService.newIntermediateCA(hostname, passphrase, intermediatePassphrase, performedBy);
  },

  /**
   * Revoke a previously issued certificate.
   *
   * @param {string} serialNumber - Serial number of the certificate.
   * @param {string} [reason] - Optional revocation reason.
   * @returns {Promise<Object>} Result of the revocation request.
   */
  revokeCertificate: async(serialNumber, reason, performedBy = undefined) => {
    const result = await revocation.revoke(serialNumber.toString(), reason, performedBy);
    if (!result) {
      return { error: 'Serial not found' };
    }
    return { revoked: true };
  },
  
  /**
   * Retrieve the certificate revocation list.
   *
   * @returns {Promise<Object>} List of revoked certificates.
   */
  getCRL: async() => {
    const revoked = await revocation.getActiveRevoked();
    return { revoked };
  },

  /**
   * Generate a PEM encoded CRL from active revocations.
   *
   * @returns {Promise<string>} PEM encoded CRL.
   */
  getCRLPem: async(passphrase) => {
    return await crlService.generatePemCrl(passphrase);
  },
};
