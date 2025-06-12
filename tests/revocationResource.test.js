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
});
