module.exports = {
  rootCA: [{
    name: 'basicConstraints',
    cA: true
  }, {
    name: 'subjectKeyIdentitifer'
  }, {
    name: 'authorityKeyIdentifier'
  }]
};
