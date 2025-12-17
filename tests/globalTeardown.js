const fs = require('fs');
const path = require('path');

module.exports = async() => {
  const dest = path.join(__dirname, '../config/test.json');
  if (fs.existsSync(dest)) {
    fs.unlinkSync(dest);
  }
  const store = path.join(__dirname, '../files_test');
  if (fs.existsSync(store)) {
    fs.rmSync(store, { recursive: true, force: true });
  }
};
