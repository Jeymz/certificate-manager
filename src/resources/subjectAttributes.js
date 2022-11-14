const forge = require('node-forge');
const config = require('./config');

const subjectConfig = config.get('subject');

module.exports = () => {
  const attributes = [];
  attributes.push({
    shortName: 'E',
    valueTagClass: forge.asn1.Type.UTF8,
    value: subjectConfig.email
  });
  attributes.push({
    shortName: 'O',
    valueTagClass: forge.asn1.Type.UTF8,
    value: subjectConfig.organization
  });
  attributes.push({
    shortName: 'L',
    valueTagClass: forge.asn1.Type.UTF8,
    value: subjectConfig.locality
  });
  attributes.push({
    shortName: 'ST',
    valueTagClass: forge.asn1.Type.UTF8,
    value: subjectConfig.state
  });
  attributes.push({
    shortName: 'C',
    valueTagClass: forge.asn1.Type.UTF8,
    value: subjectConfig.country
  });
};
