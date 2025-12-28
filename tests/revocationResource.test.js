const fs = require('fs');
const path = require('path');

let revocation;

describe('revocation resource', () => {
  beforeAll(async() => {
    await fs.promises.mkdir(path.join(__dirname, '../files_test'), { recursive: true });
  });
  beforeEach(() => {
    jest.resetModules();
    jest.spyOn(fs.promises, 'readFile').mockResolvedValue('{"certs":[]}');
    jest.spyOn(fs.promises, 'writeFile').mockResolvedValue();
    revocation = require('../src/resources/revocation');
  });

  afterEach(() => {
    fs.promises.readFile.mockRestore();
    fs.promises.writeFile.mockRestore();
  });

  test('add writes new entry', async() => {
    await revocation.add('1', 'host', 'exp');
    expect(fs.promises.writeFile).toHaveBeenCalled();
  });

  test('revoke returns null when not found', async() => {
    const result = await revocation.revoke('99');
    expect(result).toBeNull();
  });

  test('getRevoked returns revoked only', async() => {
    fs.promises.readFile.mockResolvedValueOnce('{"certs":[{"serialNumber":"1","hostname":"host","expiration":"exp","revoked":true}]}');
    const result = await revocation.getRevoked();
    expect(result).toEqual([{ serialNumber: '1', hostname: 'host', expiration: 'exp', revoked: true }]);
  });

  test('handles readFile failure gracefully', async() => {
    fs.promises.readFile.mockRejectedValueOnce(new Error('fail'));
    const result = await revocation.getRevoked();
    expect(result).toEqual([]);
  });

  test('handles parse failure gracefully', async() => {
    fs.promises.readFile.mockResolvedValueOnce('bad');
    const result = await revocation.getRevoked();
    expect(result).toEqual([]);
  });

  test('getActiveRevoked filters expired certificates', async() => {
    const now = new Date();
    const expired = new Date(now.getTime() - 1000).toISOString();
    const valid = new Date(now.getTime() + 10000).toISOString();
    fs.promises.readFile.mockResolvedValueOnce(JSON.stringify({
      certs: [
        { serialNumber: '1', hostname: 'expired', expiration: expired, revoked: true },
        { serialNumber: '2', hostname: 'valid', expiration: valid, revoked: true },
      ],
    }));
    const result = await revocation.getActiveRevoked();
    expect(result).toEqual([
      { serialNumber: '2', hostname: 'valid', expiration: valid, revoked: true },
    ]);
  });

  test('revoke updates existing entry', async() => {
    fs.promises.readFile.mockResolvedValueOnce('{"certs":[{"serialNumber":"1","hostname":"host","expiration":"exp","revoked":false}]}');
    const result = await revocation.revoke('1', 'reason');
    expect(result.revoked).toBe(true);
    expect(result.reason).toBe('reason');
    expect(fs.promises.writeFile).toHaveBeenCalled();
  });

  test('revoke ignores already revoked entry', async() => {
    fs.promises.readFile.mockResolvedValueOnce('{"certs":[{"serialNumber":"1","hostname":"host","expiration":"exp","revoked":true}]}');
    const result = await revocation.revoke('1');
    expect(result.revoked).toBe(true);
    expect(fs.promises.writeFile).not.toHaveBeenCalled();
  });

  test('getBySerial returns matching entry', async() => {
    const entry = { serialNumber: '42', hostname: 'host', expiration: 'exp', revoked: false };
    fs.promises.readFile.mockResolvedValueOnce(JSON.stringify({ certs: [entry] }));
    const result = await revocation.getBySerial('42');
    expect(result).toEqual(entry);
  });

  test('getBySerial returns null when missing', async() => {
    const result = await revocation.getBySerial('100');
    expect(result).toBeNull();
  });
});
