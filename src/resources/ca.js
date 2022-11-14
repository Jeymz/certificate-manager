const forge = require('node-forge');
const path = require('path');
const fs = require('fs');
const config = require('./config');

class CA {
  #private = {
    config: config.getOnce('ca')
  };

  constructor() {
    this.#private.store = {
      certs: path.join(this.#private.config.path, 'certs'),
      requests: path.join(this.#private.config.path, 'requests'),
      root: path.resolve(this.#private.config.path),
      log: path.join(this.#private.config.path, 'log.json'),
      serial: path.join(this.#private.config.path, 'serial'),
      caCert: path.join(this.#private.config.path, 'ca', 'ca.cert.crt'),
      caKey: path.join(this.#private.config.path, 'ca', 'ca.key.pem')
    };
    Object.keys(this.#private.store).forEach((key) => {
      if (!fs.existsSync(this.#private.store[key])) {
        throw new Error(`The path ${this.#private.store[key]} does not exist`);
      }
    });
  }

  #getSerial() {
    let serial = parseInt(fs.readFileSync(this.#private.store.serial, 'utf8'), 10);
    serial += 1;
    fs.writeFileSync(this.#private.store.serial, serial, 'utf8');
    return serial;
  }

  #unlockCA(passphrase) {
    return forge.pki.decryptRsaPrivateKey(
      fs.readFileSync(this.#private.store.caKey, 'utf8'),
      passphrase
    );
  }
}

module.exports = CA;
