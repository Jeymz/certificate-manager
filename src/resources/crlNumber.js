const fs = require('fs').promises;
const path = require('path');
const config = require('./config')();
const logger = require('../utils/logger');

class CrlNumberStore {
  constructor() {
    this.storePath = path.join(config.getStoreDirectory(), 'crlNumber');
  }

  async #persist(value) {
    await fs.mkdir(path.dirname(this.storePath), { recursive: true });
    await fs.writeFile(this.storePath, value.toString(), { encoding: 'utf-8' });
  }

  async #loadCurrent() {
    try {
      const data = await fs.readFile(this.storePath, 'utf-8');
      const parsed = parseInt(data, 10);
      if (Number.isNaN(parsed) || parsed < 0) {
        throw new Error('Invalid CRL number value');
      }
      return parsed;
    } catch (err) {
      logger.warn('Resetting CRL number store', { error: err.message });
      await this.#persist(0);
      return 0;
    }
  }

  async nextCrlNumber() {
    const current = await this.#loadCurrent();
    const nextNumber = current + 1;
    await this.#persist(nextNumber);
    return nextNumber;
  }
}

module.exports = new CrlNumberStore();
