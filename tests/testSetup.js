const fs = require('fs');
const path = require('path');

beforeAll(() => {
  const src = path.join(__dirname, '../config/defaults.example.json');
  const dest = path.join(__dirname, '../config/defaults.json');
  if (!fs.existsSync(dest)) {
    fs.copyFileSync(src, dest);
  }
});

afterAll(() => {
  const dest = path.join(__dirname, '../config/defaults.json');
  if (fs.existsSync(dest)) {
    fs.unlinkSync(dest);
  }
});
