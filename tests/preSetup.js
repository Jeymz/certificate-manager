const fs = require('fs');
const path = require('path');

const src = path.join(__dirname, '../config/defaults.example.json');
const dest = path.join(__dirname, '../config/test.json');
process.env.CONFIG_PATH = dest;
if (!fs.existsSync(dest)) {
  const contents = JSON.parse(fs.readFileSync(src, 'utf-8'));
  contents.storeDirectory = './files_test';
  fs.writeFileSync(dest, `${JSON.stringify(contents, null, 2)}\n`);
}
