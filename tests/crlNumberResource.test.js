const fs = require('fs').promises;
const os = require('os');
const path = require('path');

let mockStoreDir;

jest.mock('../src/resources/config', () => () => ({
  getStoreDirectory: jest.fn(() => mockStoreDir),
}));

const createdDirs = [];

const loadStore = async(storeDir) => {
  jest.resetModules();
  mockStoreDir = storeDir;
  createdDirs.push(storeDir);
  // eslint-disable-next-line global-require
  return require('../src/resources/crlNumber');
};

describe('crlNumber resource', () => {
  afterEach(async() => {
    await Promise.all(createdDirs.map((dir) => fs.rm(dir, { recursive: true, force: true })));
    createdDirs.length = 0;
  });

  test('creates and increments persistent CRL numbers', async() => {
    const storeDir = await fs.mkdtemp(path.join(os.tmpdir(), 'crl-number-store-'));
    const store = await loadStore(storeDir);
    const first = await store.nextCrlNumber();
    const second = await store.nextCrlNumber();

    expect(first).toBe(1);
    expect(second).toBe(2);

    const persisted = await fs.readFile(path.join(storeDir, 'crlNumber'), 'utf-8');
    expect(persisted).toBe('2');
  });

  test('resets invalid stored value to zero before incrementing', async() => {
    const storeDir = await fs.mkdtemp(path.join(os.tmpdir(), 'crl-number-store-'));
    await fs.writeFile(path.join(storeDir, 'crlNumber'), 'invalid', 'utf-8');
    const store = await loadStore(storeDir);

    const next = await store.nextCrlNumber();
    expect(next).toBe(1);
  });
});
