const crypto = require('crypto');
const forge = require('forge');
const path = require('path');
const fs = require('fs');
const config = require('../resources/config')();

// TODO: Validate workflow and convert to class
function genRSAKeypair(modulusLength = 2048, passphrase = false) {
  try {
    const validModulusLength = [1024, 2048, 4096];
    if (validModulusLength.indexOf(modulusLength) < 0) {
      return {
        error: 'Invalid modulus length provided'
      }
    }
    const returnObject = {}
    const options = {
      modulusLength,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    };
    if (typeof passphrase === 'string') {
      options.privateKeyEncoding.cipher = 'aes-256-cbc';
      options.privateKeyEncoding.passphrase = passphrase;
      returnObject.passphrase = passphrase;
    }
    const keypair = crypto.generateKeyPairSync('rsa', options);
    returnObject.privateKey = keypair.privateKey.toString();
    returnObject.publicKey = keypair.publicKey.toString();
    return returnObject;
  } catch (err) {
    return { error: 'Something unexpected happened' };
  }
}

function signCSR(csr = false, keyObject = false) {
  try {
    csr.publicKey = pki.publicKeyFromPem(keyObject.publicKey);
    if (keyObject.passphrase) {
      csr.sign(
        forge.pki.decryptRsaPrivateKey(
          keyObject.privateKey,
          passphrase
        )
      );
    } else {
      csr.sign(
        forge.pki.privateKeyFromPem(keyObject.privateKey)
      );
    }
    return {
      csr
    }
  } catch (err) {
    return { error: 'Something unexpected happened' };
  }
}

function verifyCSR(csr) {
  try {
    return {
      verified: csr.verify()
    };
  } catch (err) {
    return { error: 'Something unexpected happened' };
  }
}

function getCSRCert(csr) {
  try {
    return {
      csr: forge.pki.certificationRequestToPem(csr)
    };
  } catch (err) {
    return { error: 'Something unexpected happened' };
  }
}

function createWebsiteCSR(hostname, altnames = false) {
  try {
    const subject = config.getSubject();
    const host = config.validateHostname(hostname);
    if (!host.valid) {
      return {
        error: host.reason
      };
    }
    subject.push(host.subject);
    const challengePassword = crypto.randomBytes(32).toString('base64');
    const attributes = [
      {
        name: 'challengePassword',
        value: challengePassword
      },
      {
        name: "unstructuredName",
        value: "Robotti Tech Services LLC."
      }
    ];
    if (altnames && typeof altnames === 'object' && altnames.length > 0) {
      const extensions = {
        name: 'extensions',
        extensions: []
      }
      altnames.forEach((alternateName) => {
        extensions.extensions.push({
          type: 2,
          value: alternateName.toString()
        });
      });
      if (extensions.extensions.length > 0) {
        attributes.push(extensions);
      }
    }
    const csr = forge.pki.createCertificationRequest();
    csr.setSubject(subject);
    csr.setAttributes(attributes);
    return { csr }
  } catch (err) {
    return { error: 'Something unexpected happened' };
  }
}

module.export = {
  createWebsiteCSR: async (hostname, altnames, passphrase = false) => {
    try {
      const keypair = genRSAKeypair(2048, passphrase);
      if (keypair.error) {
        return keypair;
      }
      const csrRequest = createWebsiteCSR(hostname, altnames);
      if (csrRequest.error) {
        return csrRequest;
      }
      let { csr } = csrRequest;
      csrSigningRequest = signCSR(csr, keypair);
      if (csrSigningRequest.error) {
        return csrSigningRequest;
      }
      csr = csrSigningRequest.csr;
      const csrVerification = verifyCSR(csr)
      if (csrVerification.error) {
        return csrVerification;
      }
      if (!csrVerification.verified) {
        return { error: 'Unable to process certificate request' };
      }
      const csrCertRequest = getCSRCert(csr);
      if (csrCertRequest.error) {
        return csrCertRequest
      }
      csr = csrCertRequest.csr;
      config.signCSR(csr);
    } catch (err) {
      return { error: 'Unable to process certificate request'}
    }
  }
}

