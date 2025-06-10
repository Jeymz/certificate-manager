const fs = require('fs');
const path = require('path');

const src = path.join(__dirname, '../config/defaults.example.json');
const dest = path.join(__dirname, '../config/test.json');
process.env.CONFIG_PATH = dest;
if (!fs.existsSync(dest)) {
  fs.copyFileSync(src, dest);
}
