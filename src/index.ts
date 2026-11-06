export type CidrAction = 'allow' | 'deny';
export interface CidrRuleInput {
  cidr: string;
  action: CidrAction;
}
export interface CidrRule {
  readonly cidr: string;
  readonly action: CidrAction;
  readonly index: number;
}
export interface CidrDecision {
  action: CidrAction;
  matchedRule?: CidrRule;
}
export interface ShadowedRule {
  rule: CidrRule;
  shadowedBy: CidrRule;
}
interface Network {
  family: 4 | 6;
  bits: number;
  address: bigint;
  prefix: number;
}
const MAX_RULES = 10_000;

function ipv4(text: string): bigint {
  const parts = text.split('.');
  if (parts.length !== 4) throw new TypeError('Invalid IPv4 address.');
  let value = 0n;
  for (const part of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$(?![\s\S])/.test(part) || Number(part) > 255)
      throw new TypeError('Invalid IPv4 octet.');
    value = (value << 8n) | BigInt(part);
  }
  return value;
}

function ipv6(text: string): bigint {
  if (text.includes('.')) {
    const lastColon = text.lastIndexOf(':');
    if (lastColon < 0) throw new TypeError('Invalid embedded IPv4 address.');
    const v4 = ipv4(text.slice(lastColon + 1));
    text = `${text.slice(0, lastColon)}:${(v4 >> 16n).toString(16)}:${(v4 & 0xffffn).toString(16)}`;
  }
  if ((text.match(/::/g) ?? []).length > 1) throw new TypeError('Invalid IPv6 compression.');
  const compressed = text.includes('::');
  const halves = text.split('::');
  const left = halves[0] ? halves[0]!.split(':') : [];
  const right = compressed && halves[1] ? halves[1]!.split(':') : [];
  const words = [...left, ...right];
  if (
    words.some((word) => !/^[0-9a-fA-F]{1,4}$(?![\s\S])/.test(word)) ||
    (compressed ? words.length >= 8 : words.length !== 8)
  )
    throw new TypeError('Invalid IPv6 address.');
  const full = compressed ? [...left, ...Array(8 - words.length).fill('0'), ...right] : words;
  return full.reduce((value, word) => (value << 16n) | BigInt(`0x${word}`), 0n);
}

function parse(cidr: string): Network {
  if (typeof cidr !== 'string' || cidr.length > 128 || /[\s\r\n\0]/.test(cidr))
    throw new TypeError('Invalid CIDR input.');
  const slash = cidr.indexOf('/');
  if (slash < 1 || slash !== cidr.lastIndexOf('/'))
    throw new TypeError('CIDR requires an address and prefix.');
  const addressText = cidr.slice(0, slash),
    family = addressText.includes(':') ? 6 : 4;
  const bits = family === 4 ? 32 : 128;
  const prefixText = cidr.slice(slash + 1);
  if (!/^(?:0|[1-9]\d{0,2})$(?![\s\S])/.test(prefixText))
    throw new TypeError('Invalid CIDR prefix.');
  const prefix = Number(prefixText);
  if (prefix > bits) throw new TypeError('CIDR prefix exceeds address width.');
  const address = family === 4 ? ipv4(addressText) : ipv6(addressText);
  const hostBits = BigInt(bits - prefix);
  const mask = prefix === 0 ? 0n : ((1n << BigInt(bits)) - 1n) ^ ((1n << hostBits) - 1n);
  const networkAddress = address & mask;
  return { family, bits, address: networkAddress, prefix };
}

function contains(network: Network, candidate: Network): boolean {
  if (network.family !== candidate.family || network.prefix > candidate.prefix) return false;
  const hostBits = BigInt(network.bits - network.prefix);
  const mask =
    network.prefix === 0 ? 0n : ((1n << BigInt(network.bits)) - 1n) ^ ((1n << hostBits) - 1n);
  return (candidate.address & mask) === network.address;
}

function canonical(network: Network): string {
  let address: string;
  if (network.family === 4) {
    address = [24n, 16n, 8n, 0n]
      .map((shift) => Number((network.address >> shift) & 255n))
      .join('.');
  } else {
    const words = Array.from({ length: 8 }, (_, i) =>
      Number((network.address >> BigInt((7 - i) * 16)) & 0xffffn).toString(16),
    );
    address = words.join(':');
  }
  return `${address}/${network.prefix}`;
}

export function createCidrPolicy(
  input: readonly CidrRuleInput[],
  defaultAction: CidrAction = 'deny',
) {
  if (!Array.isArray(input) || input.length > MAX_RULES)
    throw new RangeError('CIDR rule limit exceeded.');
  if (defaultAction !== 'allow' && defaultAction !== 'deny')
    throw new TypeError('Invalid default action.');
  const parsed = input.map((item, index) => {
    if (!item || (item.action !== 'allow' && item.action !== 'deny'))
      throw new TypeError('Invalid CIDR rule.');
    const network = parse(item.cidr);
    const rule: CidrRule = Object.freeze({ cidr: canonical(network), action: item.action, index });
    return { rule, network };
  });
  const rules = Object.freeze(parsed.map(({ rule }) => rule));
  return Object.freeze({
    rules,
    evaluate(address: string): CidrDecision {
      const candidate = parse(`${address}${address.includes(':') ? '/128' : '/32'}`);
      const found = parsed.find(({ network }) => contains(network, candidate));
      return found
        ? { action: found.rule.action, matchedRule: found.rule }
        : { action: defaultAction };
    },
    shadowed(): ShadowedRule[] {
      const result: ShadowedRule[] = [];
      for (let i = 0; i < parsed.length; i++) {
        const current = parsed[i]!;
        const blocker = parsed
          .slice(0, i)
          .find((earlier) => contains(earlier.network, current.network));
        if (blocker) result.push({ rule: current.rule, shadowedBy: blocker.rule });
      }
      return result;
    },
  });
}
