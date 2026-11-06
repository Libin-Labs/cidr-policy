# @lp-labs/cidr-policy

Ordered IPv4/IPv6 CIDR allow/deny evaluator with first-match semantics and fully shadowed-rule
reporting. This is an in-memory policy helper, not network, firewall, or socket enforcement.
Independent, with zero runtime or peer dependencies.

## Install and quickstart

```bash
npm install @lp-labs/cidr-policy
```

```js
import { createCidrPolicy } from '@lp-labs/cidr-policy';

const policy = createCidrPolicy([
  { cidr: '192.0.2.0/24', action: 'allow' },
  { cidr: '192.0.2.64/26', action: 'deny' },
]);
if (policy.evaluate('192.0.2.70').action !== 'allow') throw new Error('First-match rule failed');
```

## API and semantics

- `createCidrPolicy(rules, defaultAction = 'deny')` validates/copies ordered
  `CidrRuleInput { cidr, action }` entries and returns an immutable policy.
- `evaluate(address): CidrDecision` returns `{ action, matchedRule? }`; addresses are plain IPv4
  or IPv6 literals without a prefix.
- `rules` exposes frozen canonical rules `{ cidr, action, index }`.
- `shadowed(): ShadowedRule[]` reports each later network fully covered by any earlier rule,
  including the earlier `shadowedBy` rule.
- Actions are `CidrAction = 'allow' | 'deny'`. A rule with a lower index always wins, even if a
  later rule is more specific. `defaultAction` applies when nothing matches.

IPv4 decimal octets and IPv6 hexadecimal/compressed forms (including an embedded IPv4 tail) are
parsed with BigInt arithmetic. Prefix lengths are 0–32 or 0–128. Invalid/ambiguous addresses,
leading-zero IPv4 octets, malformed prefixes and invalid actions throw `TypeError`; more than
10,000 rules throws `RangeError`.

Construction is O(R); evaluation scans rules in order, O(R); shadow analysis is O(R²), appropriate
for the 10,000-rule bounded configuration use case. This library performs no DNS lookup, socket
inspection, firewall change, routing, proxy trust resolution, or enforcement. The application
must connect the decision to its own explicitly authorized control point.

Runtime export: `createCidrPolicy`. Type exports: `CidrAction`, `CidrRuleInput`, `CidrRule`,
`CidrDecision`, `ShadowedRule`. ESM/CommonJS declarations; Node.js 18+, ES2022, no browser globals.

## Support

If this library is useful to you, consider supporting its maintenance with a [donation via PayPal](https://www.paypal.me/LibinPrasanth).

## Author

Created by [Libin Prasanth](https://www.linkedin.com/in/libinprasanth/). Connect on LinkedIn for updates and discussion.
