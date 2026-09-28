import { describe, expect, it } from 'vitest';
import type { ResolvedCase } from '../src/core/cases/scenario.ts';
import { detectKind, matches, normalise } from '../src/core/grading/indicators.ts';
import { emptyVerdict, gradeCase, MAX_SCORE, perfectVerdict, type Verdict } from '../src/core/grading/grade.ts';

function fixture(over: Partial<ResolvedCase> = {}): ResolvedCase {
  return {
    id: 'fixture~1',
    alertId: 'A1',
    templateId: 'fixture',
    seed: '1',
    category: 'identity',
    difficulty: 'tier2',
    title: 'Fixture',
    lesson: 'Fixture lesson',
    cysaDomains: [],
    kind: 'incident',
    alert: { rule: 'r', product: 'p', severity: 'high', time: '2026-09-01T10:00:00.000Z', summary: 's', entities: [], fields: [] },
    briefing: 'b',
    attachments: [],
    truth: { disposition: 'true-positive', severity: 'high', action: 'escalate', techniques: ['T1110.003', 'T1078.004'], tactics: ['credential-access'], alsoAccept: ['T1078'] },
    evidence: [
      { id: 'spray', label: 'Spray', why: 'w', recordIds: ['AAAAAAAAA1', 'AAAAAAAAA2'] },
      { id: 'success', label: 'Success', why: 'w', recordIds: ['BBBBBBBBB1'] },
    ],
    indicators: {
      block: [{ kind: 'ip', value: '203.0.113.7' }, { kind: 'domain', value: 'contoso-login7.com' }],
      scope: [{ kind: 'user', value: 'ana.lopez@contoso.com', aliases: ['ana.lopez', 'Ana Lopez'] }],
      mustNot: [{ kind: 'ip', value: '198.51.100.20', note: 'Office egress' }],
    },
    hints: ['h1', 'h2', 'h3'],
    solution: [],
    rubric: [{ id: 'mfa', text: 'Mentions MFA', keywords: ['mfa', 'multi-factor'] }],
    explanation: ['e'],
    pitfalls: ['p'],
    references: [],
    ...over,
  };
}

const benign = (): ResolvedCase =>
  fixture({
    kind: 'benign',
    truth: { disposition: 'benign', severity: 'informational', action: 'close', techniques: [], tactics: [] },
    indicators: { block: [], scope: [], mustNot: [{ kind: 'host', value: 'SCAN01' }] },
  });

const component = (g: ReturnType<typeof gradeCase>, id: string) => g.components.find((c) => c.id === id)!;
const verdict = (over: Partial<Verdict>): Verdict => ({ ...emptyVerdict(), ...over });

describe('indicator normalisation and matching', () => {
  it('refangs and trims', () => {
    expect(normalise(' hxxps://Contoso-Login7[.]com/path ')).toBe('https://contoso-login7.com/path');
    expect(normalise('"203.0.113[.]7"')).toBe('203.0.113.7');
    expect(normalise('contoso-login7.com.')).toBe('contoso-login7.com');
  });

  it('detects kinds', () => {
    expect(detectKind('203.0.113.7')).toBe('ip');
    expect(detectKind('2001:db8::5')).toBe('ip');
    expect(detectKind('a'.repeat(64))).toBe('sha256');
    expect(detectKind('hxxps://x[.]com/a')).toBe('url');
    expect(detectKind('ana.lopez@contoso.com')).toBe('email');
    expect(detectKind('CONTOSO\\ana.lopez')).toBe('user');
    expect(detectKind('ana.lopez')).toBe('user');
    expect(detectKind('invoice.iso')).toBe('file');
    expect(detectKind('contoso-login7[.]com')).toBe('domain');
    expect(detectKind('LT-FIN-004')).toBe('host');
    expect(detectKind('DC01')).toBe('host');
  });

  it('matches domains through URLs, subdomains and email addresses', () => {
    const spec = { kind: 'domain' as const, value: 'contoso-login7.com' };
    for (const v of ['contoso-login7[.]com', 'hxxps://contoso-login7.com/owa', 'auth.contoso-login7.com', 'ceo@contoso-login7.com']) {
      expect(matches({ kind: 'domain', value: v }, spec), v).toBe(true);
    }
    expect(matches({ kind: 'domain', value: 'contoso-login7.com.evil.net' }, spec)).toBe(false);
    expect(matches({ kind: 'domain', value: 'xcontoso-login7.com' }, spec)).toBe(false);
  });

  it('does not let a registered domain swallow a more specific spec', () => {
    const spec = { kind: 'domain' as const, value: 'settings-win.data.microsoft.com' };
    expect(matches({ kind: 'domain', value: 'microsoft.com' }, spec)).toBe(false);
  });

  it('matches users in UPN, sam, DOMAIN\\sam and display forms', () => {
    const spec = { kind: 'user' as const, value: 'ana.lopez@contoso.com', aliases: ['ana.lopez', 'Ana Lopez'] };
    for (const v of ['ANA.LOPEZ@contoso.com', 'CONTOSO\\ana.lopez', 'ana.lopez', 'ana lopez']) expect(matches({ kind: 'user', value: v }, spec), v).toBe(true);
    expect(matches({ kind: 'user', value: 'ana.lopes' }, spec)).toBe(false);
  });

  it('matches an IP inside a URL or with a port', () => {
    const spec = { kind: 'ip' as const, value: '192.0.2.145' };
    for (const v of ['http://192.0.2.145/cdn/884143.txt', 'hxxp://192.0.2[.]145:8080/x', '192.0.2.145:443']) expect(matches({ kind: detectKind(v), value: v }, spec), v).toBe(true);
    expect(matches({ kind: 'url', value: 'http://192.0.2.14/x' }, spec)).toBe(false);
  });

  it('matches hosts by short name or FQDN, files by basename', () => {
    expect(matches({ kind: 'host', value: 'lt-fin-004.corp.contoso.com' }, { kind: 'host', value: 'LT-FIN-004' })).toBe(true);
    expect(matches({ kind: 'host', value: 'LT-FIN-005' }, { kind: 'host', value: 'LT-FIN-004' })).toBe(false);
    expect(matches({ kind: 'file', value: 'C:\\Users\\ana\\Downloads\\Invoice.iso' }, { kind: 'file', value: 'invoice.iso' })).toBe(true);
  });
});

describe('gradeCase', () => {
  it('scores a perfect verdict at 100 and an empty one at 0', () => {
    const c = fixture();
    expect(MAX_SCORE).toBe(100);
    expect(gradeCase(c, perfectVerdict(c)).score).toBe(100);
    expect(gradeCase(c, emptyVerdict()).score).toBe(0);
  });

  it('gives nothing for an untouched benign alert, but credits restraint once a verdict is given', () => {
    const c = benign();
    expect(gradeCase(c, emptyVerdict()).score).toBe(0);
    const g = gradeCase(c, verdict({ disposition: 'benign' }));
    expect(component(g, 'attack').earned).toBe(15);
    expect(component(g, 'indicators').earned).toBe(15);
    expect(g.score).toBe(30 + 15 + 15);
  });

  it('gives half credit for a false-positive/benign mix-up and none for calling a true positive benign', () => {
    const b = benign();
    expect(component(gradeCase(b, verdict({ disposition: 'false-positive' })), 'disposition').earned).toBe(15);
    expect(component(gradeCase(fixture(), verdict({ disposition: 'benign' })), 'disposition').earned).toBe(0);
    expect(component(gradeCase(b, verdict({ disposition: 'true-positive' })), 'disposition').earned).toBe(0);
  });

  it('grades severity and action by distance', () => {
    const c = fixture();
    expect(component(gradeCase(c, verdict({ severity: 'critical' })), 'severity').earned).toBe(5);
    expect(component(gradeCase(c, verdict({ severity: 'low' })), 'severity').earned).toBe(0);
    expect(component(gradeCase(c, verdict({ action: 'monitor' })), 'action').earned).toBe(5);
    expect(component(gradeCase(c, verdict({ action: 'close' })), 'action').earned).toBe(0);
  });

  it('credits ATT&CK siblings by half, tolerates alsoAccept and penalises extras', () => {
    const c = fixture();
    const attack = (techniques: string[]) => gradeCase(c, verdict({ disposition: 'true-positive', techniques }));
    expect(component(attack(['T1110.003', 'T1078.004']), 'attack').earned).toBe(15);
    expect(component(attack(['T1110.003', 'T1078.004', 'T1078']), 'attack').earned).toBe(15);
    expect(attack(['T1110.003', 'T1078.004', 'T1078']).techniques.accepted).toEqual(['T1078']);
    // An accepted parent standing in for a missing sub-technique still earns
    // the sibling half-credit — never less than a wrong sibling would.
    expect(attack(['T1110.003', 'T1078']).techniques.partial).toEqual(['T1078']);
    expect(component(attack(['T1110.003', 'T1078']), 'attack').earned).toBe(component(attack(['T1110.003', 'T1078.001']), 'attack').earned);
    // T1110.001 is a sibling of T1110.003: half credit for that half.
    expect(component(attack(['T1110.001', 'T1078.004']), 'attack').earned).toBe(Math.round(0.75 * 15));
    expect(component(attack(['T1110.003', 'T1078.004', 'T1486']), 'attack').earned).toBe(13);
    expect(attack(['T1110.003']).techniques.missed).toEqual(['T1078.004']);
    // An exact tag plus its sibling counts once, not one and a half times.
    const both = attack(['T1110.001', 'T1110.003']);
    expect(both.techniques.matched).toEqual(['T1110.003']);
    expect(both.techniques.extra).toEqual(['T1110.001']);
    expect(component(both, 'attack').earned).toBe(Math.round(0.5 * 15) - 2);
  });

  it('penalises tagging techniques on a benign case', () => {
    const g = gradeCase(benign(), verdict({ disposition: 'benign', techniques: ['T1046'] }));
    expect(component(g, 'attack').earned).toBe(10);
  });

  it('counts evidence by pinned rows, reduced by hints and excess irrelevant pins', () => {
    const c = fixture();
    expect(component(gradeCase(c, verdict({ pins: ['AAAAAAAAA2'] })), 'evidence').earned).toBe(10);
    expect(component(gradeCase(c, verdict({ pins: ['AAAAAAAAA1', 'BBBBBBBBB1'], hintsUsed: 2 })), 'evidence').earned).toBe(12);
    // Hints beyond the case's own count don't push below the floor.
    expect(component(gradeCase(c, verdict({ pins: ['AAAAAAAAA1', 'BBBBBBBBB1'], hintsUsed: 99 })), 'evidence').earned).toBe(8);
    const noisy = ['AAAAAAAAA1', 'BBBBBBBBB1', ...Array.from({ length: 7 }, (_, i) => `ZZZZZZZZZ${i}`)];
    const g = gradeCase(c, verdict({ pins: noisy }));
    expect(g.irrelevantPins).toBe(7);
    expect(component(g, 'evidence').earned).toBe(20 - 3);
  });

  it('weights block and scope indicators and penalises must-not and unsupported ones', () => {
    const c = fixture();
    const ind = (list: string[]) => component(gradeCase(c, verdict({ indicators: list.map((value) => ({ kind: detectKind(value), value })) })), 'indicators');
    expect(ind(['203.0.113.7', 'hxxps://contoso-login7[.]com/x', 'CONTOSO\\ana.lopez']).earned).toBe(15);
    expect(ind(['203.0.113.7']).earned).toBe(5);
    expect(ind(['ana.lopez@contoso.com']).earned).toBe(5);
    expect(ind(['203.0.113.7', 'contoso-login7.com', 'ana.lopez', '198.51.100.20']).earned).toBe(10);
    expect(ind(['203.0.113.7', 'contoso-login7.com', 'ana.lopez', '192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4']).earned).toBe(15 - 6);
    // Duplicates in different spellings count once.
    const g = gradeCase(c, verdict({ indicators: [{ kind: 'ip', value: '203.0.113.7' }, { kind: 'ip', value: '203.0.113[.]7' }] }));
    expect(g.indicators.results).toHaveLength(1);
    expect(component(g, 'indicators').earned).toBe(5);
  });

  it('credits an email address and its domain as two separate indicators', () => {
    const c = fixture({ indicators: { block: [{ kind: 'domain', value: 'contoso-login7.com' }, { kind: 'email', value: 'ceo@contoso-login7.com' }], scope: [], mustNot: [] } });
    const g = gradeCase(c, verdict({ indicators: [{ kind: 'email', value: 'ceo@contoso-login7.com' }, { kind: 'domain', value: 'contoso-login7.com' }] }));
    expect(g.indicators.missedBlock).toEqual([]);
    expect(component(g, 'indicators').earned).toBe(15);
  });

  it('flags must-not indicators on a benign case', () => {
    const g = gradeCase(benign(), verdict({ disposition: 'benign', indicators: [{ kind: 'host', value: 'scan01.corp.contoso.com' }] }));
    expect(g.indicators.results[0].verdict).toBe('must-not');
    expect(component(g, 'indicators').earned).toBe(10);
  });

  it('awards rubric hits and difficulty-weighted XP', () => {
    const c = fixture();
    const g = gradeCase(c, { ...perfectVerdict(c), notes: 'Reset creds and enforce Multi-Factor for the account.' });
    expect(g.rubricHits).toEqual(['mfa']);
    expect(g.xp).toBe(100 * 1.5 + 3);
  });
});
