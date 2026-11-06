import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createCidrPolicy } from '../dist/esm/index.js';

test('matches IPv4 networks and applies default deny', () => {
  const policy = createCidrPolicy([{ cidr: '192.0.2.0/24', action: 'allow' }]);
  assert.equal(policy.evaluate('192.0.2.44').action, 'allow');
  assert.equal(policy.evaluate('192.0.3.1').action, 'deny');
});
test('matches IPv6 compressed addresses and canonicalizes networks', () => {
  const policy = createCidrPolicy([{ cidr: '2001:db8::1/64', action: 'allow' }]);
  assert.equal(policy.rules[0].cidr, '2001:db8:0:0:0:0:0:0/64');
  assert.equal(policy.evaluate('2001:db8::ffff').action, 'allow');
});
test('uses first-match order for narrower and broader allow/deny rules', () => {
  const policy = createCidrPolicy([
    { cidr: '10.0.0.0/8', action: 'deny' },
    { cidr: '10.1.0.0/16', action: 'allow' },
  ]);
  assert.equal(policy.evaluate('10.1.2.3').action, 'deny');
  assert.deepEqual(
    policy.shadowed().map(({ rule, shadowedBy }) => [rule.index, shadowedBy.index]),
    [[1, 0]],
  );
});
test('reports only fully shadowed later subnets', () => {
  const policy = createCidrPolicy([
    { cidr: '192.0.2.0/25', action: 'deny' },
    { cidr: '192.0.2.0/24', action: 'allow' },
    { cidr: '192.0.2.0/26', action: 'allow' },
  ]);
  assert.deepEqual(
    policy.shadowed().map(({ rule }) => rule.index),
    [2],
  );
});
test('supports IPv4-mapped IPv6 spellings and validates invalid CIDRs', () => {
  const policy = createCidrPolicy([{ cidr: '::ffff:192.0.2.0/120', action: 'allow' }]);
  assert.equal(policy.evaluate('::ffff:c000:201').action, 'allow');
  for (const cidr of ['10.0.0.1', '10.0.0.0/33', '10.00.0.0/8', '2001::1::2/64', '192.0.2.0/24\n'])
    assert.throws(() => createCidrPolicy([{ cidr, action: 'deny' }]), TypeError);
});
test('rejects invalid addresses, actions, and oversized rule sets', () => {
  const policy = createCidrPolicy([]);
  assert.throws(() => policy.evaluate('999.1.1.1'), TypeError);
  assert.throws(() => createCidrPolicy([{ cidr: '0.0.0.0/0', action: 'permit' }]), TypeError);
  assert.throws(
    () => createCidrPolicy(Array(10_001).fill({ cidr: '0.0.0.0/0', action: 'deny' })),
    RangeError,
  );
});
test('CommonJS exposes independent policy creation', () => {
  const api = createRequire(import.meta.url)('../dist/cjs/index.js');
  assert.deepEqual(Object.keys(api), ['createCidrPolicy']);
  assert.equal(api.createCidrPolicy([]).evaluate('::1').action, 'deny');
});
