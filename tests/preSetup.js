const fs = require('fs');
const path = require('path');

const src = path.join(__dirname, '../config/defaults.example.json');
const dest = path.join(__dirname, '../config/defaults.json');
const testStatus = path.join(__dirname, '../config/testStatus.txt');
if (!fs.existsSync(dest)) {
  fs.writeFileSync(testStatus, "testing");
  fs.copyFileSync(src, dest);
} else if (!fs.existsSync(testStatus)) {
  process.exit(1);
}
