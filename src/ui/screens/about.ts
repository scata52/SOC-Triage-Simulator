import type { App } from '../app.ts';
import { ALL_TEMPLATES } from '../../data/templates/index.ts';
import { CYSA_DOMAINS } from '../../data/cysa.ts';
import { MITRE_TECHNIQUES } from '../../data/mitre.ts';
import { POINTS } from '../../engine/grading.ts';
import { RANKS } from '../../state/store.ts';
import { h } from '../dom.ts';

export function renderAbout(app: App): HTMLElement {
  return h(
    'div',
    { class: 'about prose' },
    h('h1', null, 'About'),
    h(
      'p',
      { class: 'lede' },
      'A practice queue for security analysts. Each case is a synthetic alert with the evidence behind it, and you triage it the way you would on shift: what is it, how bad is it, what happens next, and which adversary technique does it map to.',
    ),

    h('h2', null, 'How a case works'),
    h(
      'ol',
      null,
      h('li', null, h('strong', null, 'Read the alert and the evidence.'), ' Windows Security and Sysmon events, Entra ID sign-in logs, email headers, proxy/firewall/DNS records, EDR detections — the same sources you would pivot through in a SIEM.'),
      h('li', null, h('strong', null, 'Disposition.'), ' True Positive (malicious activity happened), False Positive (the detection fired wrongly), or Benign (real activity, but expected and authorised — a sanctioned scan, an admin doing admin things).'),
      h('li', null, h('strong', null, 'Severity and action.'), ' How bad it is if real, and whether you close, keep monitoring, or escalate to incident response.'),
      h('li', null, h('strong', null, 'ATT&CK technique.'), ' Tag what the adversary did using MITRE ATT&CK. Benign and false-positive cases get no technique — that is a deliberate part of the test.'),
      h('li', null, h('strong', null, 'Notes.'), ' Write the ticket. The answer key includes a checklist of the points a strong analyst would have captured.'),
    ),

    h('h2', null, 'Scoring'),
    h(
      'p',
      null,
      `Each case is out of 100: disposition ${POINTS.disposition}, severity ${POINTS.severity} (half credit one level off), action ${POINTS.action} (half credit for the adjacent choice), and ATT&CK ${POINTS.techniques} (partial credit for parent techniques, small penalty for extras). Notes are keyword-checked against the rubric for a small XP bonus rather than scored — free text deserves a human reader.`,
    ),
    h(
      'p',
      null,
      'XP is score × difficulty multiplier (Tier 1 ×1, Tier 2 ×1.5, Tier 3 ×2) plus 5 per rubric point covered. Ranks: ',
      RANKS.map((r) => `${r.name} (${r.minXp.toLocaleString()})`).join(' → '),
      '.',
    ),

    h('h2', null, 'What it maps to'),
    h(
      'p',
      null,
      `The ${ALL_TEMPLATES.length} scenarios are tagged with CompTIA CySA+ (CS0-003) domains and drawn from the MITRE ATT&CK Enterprise matrix (${MITRE_TECHNIQUES.length} techniques in the picker). Roughly a third of scenarios are false positives or benign, because the ability to confidently close a non-incident is the skill that separates a good Tier 1 from a noisy one.`,
    ),
    h(
      'ul',
      null,
      ...CYSA_DOMAINS.map((d) => h('li', null, h('strong', null, `${d.id} ${d.name}`), ` — ${d.blurb}`)),
    ),

    h('h2', null, 'Reading the twins'),
    h(
      'p',
      null,
      'Several scenarios come in pairs that fire the same alert with opposite answers: atypical travel that is an account takeover vs. the corporate VPN; PsExec from an attacker vs. from the management server under change control; a workstation port-scanning vs. the authorised vulnerability scanner. The alert name never decides the case — the context does.',
    ),

    h('h2', null, 'Data and privacy'),
    h(
      'p',
      null,
      'All identities, hosts, IPs, hashes and domains are generated on the fly and are not real. Your progress lives in this browser\'s local storage only; nothing is sent anywhere. Export it from the Stats page if you want a copy.',
    ),

    h('div', { class: 'form-actions' }, h('button', { class: 'btn btn-primary', type: 'button', onclick: () => app.start({ mode: 'single' }) }, 'Start a case')),
  );
}
