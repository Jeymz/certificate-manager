const Store = require('./store');

class CA {
  #private = {};

  constructor(caConfig) {
    this.#private.store = new Store(caConfig.path);
    if (this.#private.store?.getRootCA) {
      // Initialize CA
    } else {
      // Create CA
    }
  }

  #initialize() {
    this.#private.keypair = this.#private.store.getRootCA();
    this.#private.serial = this.#private.store.getSerial();
  }

  #create(caConfig) {
    
  }
}