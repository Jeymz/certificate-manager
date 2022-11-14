const path = require('path');
const fs = require('fs');

class Store {
  #private = {};

  constructor(storePath) {
    this.#private.store = {
      certs: path.join(storePath, 'certs'),
      requests: path.join(storePath, 'requests'),
      root: path.resolve(storePath),
      serial: path.join(storePath, 'serial'),
      privateKeys: path.join(storePath, 'private'),
      authorities: path.join(storePath, 'authorities'),
      rootPublic: path.join(storePath, 'authorities', 'ROOT CA.public.pem'),
      rootPrivate: path.join(storePath, 'authorities', 'ROOT CA.private.pem')
    };
    if (fs.existsSync(this.#private.store.root)) {
      throw new Error('Invalid CA path provided');
    }
    Object.keys(this.#private.store).forEach((storeKey) => {
      if (!fs.existsSync(this.#private.store[storeKey])) {
        fs.mkdirSync(this.#private.store[storeKey]);
      }
    });

    if (
      !fs.existsSync(this.#private.store.rootPublic)
      || !fs.existsSync(this.#private.store.rootPrivate)
    ) {
      this.saveRootCA = this.#saveRootCA;
    } else {
      this.getRootCA = this.#getRootCA;
    }
  }

  getCert(hostname) {
    try {
      if (!fs.existsSync(path.join(this.#private.store.certs, `${hostname}.crt`))) {
        return false;
      }
      return fs.readFileSync(path.join(this.#private.store.certs, `${hostname}.crt`), 'utf8');
    } catch {
      return false;
    }
  }

  saveCert(hostname, certificatePEM) {
    try {
      fs.writeFileSync(path.join(this.#private.certs, `${hostname}.crt`), certificatePEM);
      return true;
    } catch {
      return false;
    }
  }

  getPrivateKey(hostname) {
    try {
      if (!fs.existsSync(path.join(this.#private.store.privateKeys, `${hostname}.key`))) {
        return false;
      }
      return fs.readFileSync(path.join(this.#private.store.privateKeys, `${hostname}.key`), 'utf8');
    } catch {
      return false;
    }
  }

  savePrivateKey(hostname, privateKeyPEM) {
    try {
      fs.writeFileSync(path.join(this.#private.privateKeys, `${hostname}.key`), privateKeyPEM);
      return true;
    } catch {
      return false;
    }
  }

  getSerial() {
    if (!fs.existsSync(this.#private.store.serial)) {
      fs.writeFileSync(this.#private.store.serial, '1000000');
    }
    return parseInt(fs.readFileSync(this.#private.store.serial, 'utf8'), 10);
  }

  saveSerial(newSerial) {
    fs.writeFileSync(this.#private.store.serial, newSerial.toString());
  }

  #getRootCA() {
    return {
      private: fs.readFileSync(this.#private.store.rootPrivate, 'utf8'),
      public: fs.readFileSync(this.#private.store.rootPublic, 'utf8')
    };
  }

  #saveRootCA(privateKeyPEM, publicKeyPEM) {
    try {
      fs.writeFileSync(this.#private.rootPublic, publicKeyPEM);
      fs.writeFileSync(this.#private.rootPrivate, privateKeyPEM);
      if (this.saveRootCA) {
        delete this.saveRootCA;
        this.getRootCA = this.#getRootCA;
      }
      return true;
    } catch {
      return false;
    }
  }
}

module.exports = Store;
