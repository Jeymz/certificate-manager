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
});
