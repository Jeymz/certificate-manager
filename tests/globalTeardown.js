const fs = require('fs');
const path = require('path');

module.exports = async() => {
  const dest = path.join(__dirname, '../config/defaults.json');
  if (fs.existsSync(dest)) {
    fs.unlinkSync(dest);
  }
};
