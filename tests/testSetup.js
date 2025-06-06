const fs = require('fs');
const path = require('path');

afterAll(() => {
  const dest = path.join(__dirname, '../config/defaults.json');
  if (fs.existsSync(dest)) {
    fs.unlinkSync(dest);
  }
});
