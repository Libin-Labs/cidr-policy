import api = require('@lp-labs/cidr-policy');
const policy = api.createCidrPolicy([{ cidr: '::/0', action: 'deny' }]);
const action: api.CidrAction = policy.evaluate('2001:db8::1').action;
void action;
