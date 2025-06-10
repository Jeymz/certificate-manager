const fs = require('fs');
const path = require('path');

module.exports = async() => {
  const dest = path.join(__dirname, '../config/defaults.json');
  const testStatus = path.join(__dirname, '../config/testStatus.txt');
  if (fs.existsSync(dest) && fs.existsSync(testStatus)) {
    fs.unlinkSync(dest);
  }
  if (fs.existsSync(testStatus)) {
    fs.unlinkSync(testStatus);
  }
};
