const fs = require('fs').promises;
const path = require('path');
const logger = require('./logger');

/**
 * Ensure a file exists at the given path, creating it with default contents when missing.
 *
 * @param {string} filePath - Path of the file to check.
 * @param {string|Object} defaultContents - Contents to write if the file is missing.
 * @returns {Promise<boolean>} Resolves true when a file was created.
 */
async function ensureFile(filePath, defaultContents) {
  try {
    await fs.access(filePath);
    return false;
  } catch {
    const data = typeof defaultContents === 'string'
      ? defaultContents
      : `${JSON.stringify(defaultContents, null, 2)}\n`;
    await fs.writeFile(filePath, data, { encoding: 'utf-8' });
    logger.info(`Created missing store file: ${path.basename(filePath)}`);
    return true;
  }
}

/**
 * Validate and initialize the certificate store structure.
 *
 * @param {string} storeDirectory - Path to the CA store.
 * @returns {Promise<string[]>} List of files or directories created.
 */
async function validateStore(storeDirectory) {
  const created = [];
  const intDir = path.join(storeDirectory, 'intermediates');
  try {
    await fs.access(intDir);
  } catch {
    await fs.mkdir(intDir, { recursive: true });
    logger.info('Created missing store directory: intermediates');
    created.push('intermediates');
  }

  if (await ensureFile(path.join(storeDirectory, 'serial'), '1000000')) {
    created.push('serial');
  }
  if (await ensureFile(path.join(storeDirectory, 'log.json'), { requests: [] })) {
    created.push('log.json');
  }
  if (await ensureFile(path.join(storeDirectory, 'revoked.json'), { certs: [] })) {
    created.push('revoked.json');
  }

  return created;
}

module.exports = { validateStore, ensureFile };
