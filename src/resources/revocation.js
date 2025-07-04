const fs = require('fs').promises;
const path = require('path');
const config = require('./config')();
const logger = require('../utils/logger');

class Revocation {
  constructor() {
    this.storePath = path.join(config.getStoreDirectory(), 'revoked.json');
  }

  async _load() {
    try {
      const data = await fs.readFile(this.storePath, 'utf-8');
      try {
        return JSON.parse(data);
      } catch {
        return { certs: [] };
      }
    } catch {
      return { certs: [] };
    }
  }

  async _save(data) {
    await fs.writeFile(this.storePath, JSON.stringify(data), { encoding: 'utf-8' });
  }

  async add(serialNumber, hostname, expiration) {
    const data = await this._load();
    data.certs.push({
      serialNumber: serialNumber.toString(),
      hostname,
      expiration,
      revoked: false,
    });
    await this._save(data);
  }

  async revoke(serialNumber, reason, performedBy = undefined) {
    const data = await this._load();
    const entry = data.certs.find((c) => c.serialNumber === serialNumber.toString());
    if (!entry) {
      return null;
    }
    if (!entry.revoked) {
      entry.revoked = true;
      entry.revokedAt = new Date().toISOString();
      if (reason) {
        entry.reason = reason;
      }
      await this._save(data);
      logger.audit.info({
        timestamp: new Date().toISOString(),
        eventType: 'CERT_REVOKE',
        serialNumber: serialNumber.toString(),
        performedBy,
        reason,
      });
    }
    return entry;
  }

  async getRevoked() {
    const data = await this._load();
    return data.certs.filter((c) => c.revoked);
  }
}

module.exports = new Revocation();
