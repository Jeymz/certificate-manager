const fs = require('fs').promises;
const os = require('os');
const path = require('path');
const { validateStore } = require('../src/utils/storeValidator');

async function createStore(opts = {}) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'store-'));
  if (!opts.skipIntermediates) {
    await fs.mkdir(path.join(dir, 'intermediates'), { recursive: true });
  }
  if (!opts.skipSerial) {
    await fs.writeFile(path.join(dir, 'serial'), '1');
  }
  if (!opts.skipLog) {
    await fs.writeFile(path.join(dir, 'log.json'), JSON.stringify({ requests: [] }));
  }
  if (!opts.skipRevoked) {
    await fs.writeFile(path.join(dir, 'revoked.json'), JSON.stringify({ certs: [] }));
  }
  return dir;
}

async function cleanup(dir) {
  await fs.rm(dir, { recursive: true, force: true });
}

describe('validateStore utility', () => {
  test('creates all files when store empty', async() => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'store-'));
    const created = await validateStore(dir);
    expect(created).toEqual(expect.arrayContaining(['serial', 'log.json', 'revoked.json', 'intermediates']));
    await cleanup(dir);
  });

  test('creates missing serial file', async() => {
    const dir = await createStore({ skipSerial: true });
    const created = await validateStore(dir);
    expect(created).toContain('serial');
    expect(created.length).toBe(1);
    await cleanup(dir);
  });

  test('creates missing log.json file', async() => {
    const dir = await createStore({ skipLog: true });
    const created = await validateStore(dir);
    expect(created).toContain('log.json');
    expect(created.length).toBe(1);
    await cleanup(dir);
  });

  test('creates missing revoked.json file', async() => {
    const dir = await createStore({ skipRevoked: true });
    const created = await validateStore(dir);
    expect(created).toContain('revoked.json');
    expect(created.length).toBe(1);
    await cleanup(dir);
  });

  test('creates missing intermediates directory', async() => {
    const dir = await createStore({ skipIntermediates: true });
    const created = await validateStore(dir);
    expect(created).toContain('intermediates');
    expect(created.length).toBe(1);
    await cleanup(dir);
  });

  test('no changes when all files present', async() => {
    const dir = await createStore();
    const created = await validateStore(dir);
    expect(created).toEqual([]);
    await cleanup(dir);
  });

  test('idempotent across calls', async() => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'store-'));
    await validateStore(dir);
    const created = await validateStore(dir);
    expect(created).toEqual([]);
    await cleanup(dir);
  });
});
