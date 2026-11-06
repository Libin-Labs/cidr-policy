import { createCidrPolicy, type CidrRuleInput } from '@lp-labs/cidr-policy';
const rules: CidrRuleInput[] = [{ cidr: '192.0.2.0/24', action: 'allow' }];
const decision = createCidrPolicy(rules).evaluate('192.0.2.1');
// @ts-expect-error rule actions are allow or deny.
createCidrPolicy([{ cidr: '192.0.2.0/24', action: 'permit' }]);
void decision;
