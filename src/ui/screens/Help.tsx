import { KQL_REFERENCE, type RefKind } from '../../core/query/kql/reference.ts';
import { TABLES } from '../../core/logs/schema.ts';
import { POINTS, HINT_PENALTY, FREE_EXTRA_PINS, DIFFICULTY_MULTIPLIER } from '../../core/grading/grade.ts';
import { CASE_SHARE, PRIORITY_SHARE, CLEAN_SHIFT_BONUS } from '../../core/shift/score.ts';
import { RANKS } from '../../state/profile.ts';
import { CYSA_DOMAINS } from '../../core/taxonomy/cysa.ts';
import { MITRE_TECHNIQUES } from '../../core/taxonomy/mitre.ts';
import { ALERT_TYPES } from '../lib/cases.ts';

const SECTIONS = [
  ['start', 'How it works'],
  ['kql', 'KQL in five minutes'],
  ['reference', 'Query reference'],
  ['tables', 'Tables'],
  ['grading', 'Grading'],
  ['keys', 'Keyboard'],
  ['about', 'About the data'],
] as const;

type Section = (typeof SECTIONS)[number][0];

const KIND_TITLES: Record<RefKind, string> = {
  statement: 'Statements',
  operator: 'Tabular operators',
  'string-operator': 'Comparison and string operators',
  aggregate: 'Aggregations (summarize)',
  scalar: 'Scalar functions',
};

function Start() {
  return (
    <>
      <h1>How it works</h1>
      <p class="lede">
        A training SOC. Alerts fire in a fictional company; behind each one is a full day of that company's logs — thousands of rows of ordinary activity with the
        attack (or the innocent explanation) somewhere inside. You investigate with real queries and make the call.
      </p>
      <h2>Ways to play</h2>
      <ul>
        <li>
          <strong>Shift</strong> — the main event. Six to nine alerts in one queue, sharing one set of logs, on a clock. Prioritise: the real incidents matter more,
          and matter more the sooner you reach them.
        </li>
        <li>
          <strong>Campaign</strong> — runs quietly across your shifts. A fictional threat actor works through a playbook against your company, one step per shift. Catch
          a step and escalate it, and incident response contains it; miss it and the actor moves on — on the same victim, with the same infrastructure. You will not
          be told which alert is which.
        </li>
        <li>
          <strong>Study</strong> — single cases on a spaced-repetition schedule, weighted toward your weakest ATT&CK tactics and CySA+ domains.
        </li>
        <li>
          <strong>Practice</strong> — any of the {ALERT_TYPES.length} alert types, as often as you like; every start is a new variation.
        </li>
        <li>
          <strong>Case of the day</strong> — the same case for everyone, in a shared fictional company.
        </li>
      </ul>
      <h2>Making the call</h2>
      <dl class="kv">
        <dt>True positive</dt>
        <dd>Malicious activity happened.</dd>
        <dt>False positive</dt>
        <dd>The detection fired wrongly — nothing of what it describes took place.</dd>
        <dt>Benign</dt>
        <dd>The activity is real but expected or authorised: the vulnerability scanner, an admin under a change ticket, a phishing simulation.</dd>
      </dl>
      <p>
        Many detections come in <strong>twins</strong>: the same alert, the same title, opposite answers. Atypical travel that is a stolen session vs. the corporate VPN;
        PsExec from an intruder vs. from the management server. The alert never decides the case — the logs around it do.
      </p>
      <h2>Evidence and indicators</h2>
      <p>
        Every row in every table has a <code>RecordId</code>. When a query returns raw rows, each gets a pin button: pin the rows that prove your conclusion. Aggregated
        results (after <code>summarize</code>) cannot be pinned — go back to the rows. Indicators are what should be blocked (attacker IPs, domains, hashes) and who or
        what is affected (users, hosts). Don't report your own company's infrastructure: the office egress IP, the VPN, the sanctioned scanner.
      </p>
    </>
  );
}

function Kql() {
  return (
    <>
      <h1>KQL in five minutes</h1>
      <p class="lede">
        Kusto Query Language reads top to bottom: start from a table, then pipe rows through operators. The console supports the subset below; SQL (SQLite) works too
        if you prefer.
      </p>
      <h2>1. Start from a table, filter early</h2>
      <pre class="code-block mono">{'SigninLogs\n| where TimeGenerated > ago(6h)\n| where ResultType != 0\n| take 50'}</pre>
      <p>
        <code>ago(6h)</code> is relative to <code>now()</code> — the end of the case's log window, not your wall clock. Times are UTC.
      </p>
      <h2>2. has vs contains</h2>
      <pre class="code-block mono">{'DeviceProcessEvents\n| where ProcessCommandLine has "-enc"\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine'}</pre>
      <p>
        <code>has</code> matches whole terms (fast, precise); <code>contains</code> matches any substring. Both are case-insensitive; add <code>_cs</code> for
        case-sensitive.
      </p>
      <h2>3. Count things</h2>
      <pre class="code-block mono">{'SigninLogs\n| where ResultType != 0\n| summarize Failures = count(), Users = dcount(UserPrincipalName) by IPAddress\n| sort by Users desc'}</pre>
      <p>One IP failing against many users is a spray; many IPs failing against one user is brute force.</p>
      <h2>4. Over time</h2>
      <pre class="code-block mono">{'WebProxy\n| where DestinationHost == "example-host.test"\n| summarize count() by bin(TimeGenerated, 5m)\n| render timechart'}</pre>
      <h2>5. Look everywhere</h2>
      <pre class="code-block mono">{'search "LT-FIN-004"\n| take 100'}</pre>
      <p>
        <code>search</code> scans every table — the fastest way to pivot on an entity from the alert. Its results can be pinned too.
      </p>
      <h2>6. Join to context</h2>
      <pre class="code-block mono">{'SigninLogs\n| where ResultType == 0\n| join kind=inner (IdentityInfo | project AccountUpn, Department, JobTitle) on $left.UserPrincipalName == $right.AccountUpn'}</pre>
      <p>
        Context tables — <code>IdentityInfo</code>, <code>DeviceInfo</code>, <code>Tickets</code>, <code>ThreatIntel</code>, <code>IncidentHistory</code> — are how you
        tell an attacker from an admin doing their job.
      </p>
      <p>
        Press <kbd>Ctrl</kbd>+<kbd>Space</kbd> in the editor for suggestions. See the <a href="#/help/reference">full reference</a>.
      </p>
    </>
  );
}

function Reference() {
  const kinds: RefKind[] = ['statement', 'operator', 'string-operator', 'aggregate', 'scalar'];
  return (
    <>
      <h1>Query reference</h1>
      <p class="lede">Everything the console understands. Every example here is run by the test suite against real case data, so it works.</p>
      {kinds.map((k) => (
        <section aria-labelledby={`ref-${k}`}>
          <h2 id={`ref-${k}`}>{KIND_TITLES[k]}</h2>
          {KQL_REFERENCE.filter((e) => e.kind === k).map((e) => (
            <div class="ref-entry">
              <h3>{e.name}</h3>
              <p class="small">
                <code>{e.syntax}</code> — {e.doc}
              </p>
              <pre class="code-block mono">{e.example}</pre>
            </div>
          ))}
        </section>
      ))}
      <h2>SQL mode</h2>
      <p>
        Switch the console to SQL for SQLite syntax: one read-only <code>SELECT</code> (or <code>WITH … SELECT</code>) statement. KQL's string helpers are available as
        functions: <code>kql_has(text, term, 0)</code> and <code>kql_contains(text, part, 0)</code> (last argument 1 for case-sensitive),{' '}
        <code>kql_regex(text, pattern)</code>, <code>kql_extract(pattern, group, text)</code> and <code>kql_b64decode(text)</code>.
      </p>
      <pre class="code-block mono">{"SELECT TimeGenerated, DeviceName, ProcessCommandLine\nFROM DeviceProcessEvents\nWHERE kql_has(ProcessCommandLine, 'hidden', 0)\nORDER BY TimeGenerated DESC\nLIMIT 20"}</pre>
      <p class="small muted">Column and table names are the same in both languages.
      </p>
    </>
  );
}

function Tables() {
  return (
    <>
      <h1>Tables</h1>
      <p class="lede">A Microsoft Sentinel / Defender-style schema. Log tables record events inside the case window; context tables describe the organisation.</p>
      {TABLES.map((t) => (
        <details class="disclosure" style={{ marginBottom: 6 }}>
          <summary>
            <span class="mono">{t.name}</span> <span class="badge">{t.kind}</span>
          </summary>
          <div class="disclosure-body">
            <p class="small">{t.doc}</p>
            <table class="table">
              <caption class="visually-hidden">Columns of {t.name}</caption>
              <thead>
                <tr>
                  <th scope="col">Column</th>
                  <th scope="col">Type</th>
                  <th scope="col">Meaning</th>
                </tr>
              </thead>
              <tbody>
                {t.columns.map((c) => (
                  <tr>
                    <td class="mono small">{c.name}</td>
                    <td class="mono small faint">{c.type}</td>
                    <td class="small">{c.doc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      ))}
    </>
  );
}

function Grading() {
  return (
    <>
      <h1>Grading</h1>
      <p class="lede">Each case is out of 100. The first four parts grade your conclusion; the last two grade your investigation.</p>
      <table class="table">
        <caption class="visually-hidden">Points per component</caption>
        <tbody>
          <tr>
            <th scope="row">Disposition</th>
            <td class="num mono">{POINTS.disposition}</td>
            <td class="small">Exact match. False positive vs benign: half — both are non-malicious.</td>
          </tr>
          <tr>
            <th scope="row">Severity</th>
            <td class="num mono">{POINTS.severity}</td>
            <td class="small">Half credit one step off.</td>
          </tr>
          <tr>
            <th scope="row">Action</th>
            <td class="num mono">{POINTS.action}</td>
            <td class="small">Close · monitor · escalate; half credit for the adjacent choice.</td>
          </tr>
          <tr>
            <th scope="row">ATT&CK</th>
            <td class="num mono">{POINTS.attack}</td>
            <td class="small">Credit per required technique (half for a sibling sub-technique), −2 per unsupported tag. Some cases accept defensible alternatives. Tagging a benign case costs 5 per tag.</td>
          </tr>
          <tr>
            <th scope="row">Evidence</th>
            <td class="num mono">{POINTS.evidence}</td>
            <td class="small">
              Share of the key findings you pinned (any row of a finding counts). Each hint costs {Math.round(HINT_PENALTY * 100)}% of this part. More than {FREE_EXTRA_PINS} irrelevant pins costs
              a point each (up to 5).
            </td>
          </tr>
          <tr>
            <th scope="row">Indicators</th>
            <td class="num mono">{POINTS.indicators}</td>
            <td class="small">
              What to block and who is affected. Defanged, URL, <code>DOMAIN\user</code> and FQDN spellings all count. Flagging your own or legitimate infrastructure
              costs 5 each; guesses the logs don't support cost 2 each (up to 6). When nothing needs reporting, reporting nothing is full marks.
            </td>
          </tr>
        </tbody>
      </table>
      <h2>XP and ranks</h2>
      <p>
        XP = score × difficulty (Tier 1 ×{DIFFICULTY_MULTIPLIER.tier1}, Tier 2 ×{DIFFICULTY_MULTIPLIER.tier2}, Tier 3 ×{DIFFICULTY_MULTIPLIER.tier3}) + 3 per point your
        handover note covers. Ranks: {RANKS.map((r) => `${r.name} (${r.minXp.toLocaleString()})`).join(' → ')}.
      </p>
      <h2>Shifts</h2>
      <p>
        Shift score = {CASE_SHARE}% verdict quality (weighted by true severity, with real incidents weighing more) + {PRIORITY_SHARE}% prioritisation — how close your
        handling order came to the ideal (real, escalation-worthy incidents by severity first), measured as nDCG. Alerts left in the queue score zero. A clean shift
        (no missed incidents, no false escalations, nothing left) earns {CLEAN_SHIFT_BONUS} bonus XP.
      </p>
    </>
  );
}

function Keys() {
  return (
    <>
      <h1>Keyboard</h1>
      <p class="lede">Everything works without a mouse.</p>
      <table class="table">
        <caption class="visually-hidden">Keyboard shortcuts</caption>
        <tbody>
          {[
            ['Ctrl/⌘ + Enter, Shift + Enter', 'Run the query (in the editor)'],
            ['Ctrl + Space', 'Suggestions in the editor'],
            ['Tab / Shift + Tab', 'Leave the editor and move between controls (the editor never traps Tab)'],
            ['← → Home End', 'Move between tabs in a tab list'],
            ['↑ ↓ Enter Esc', 'Choose an ATT&CK technique in the picker'],
            ['Enter', 'Add an indicator from the indicator box'],
            ['Esc', 'Close a dialog'],
            ['First Tab on any page', 'Skip to content'],
          ].map(([k, d]) => (
            <tr>
              <th scope="row" class="mono small" style={{ textTransform: 'none', letterSpacing: 0, color: 'var(--text)' }}>
                {k}
              </th>
              <td class="small">{d}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p class="small muted">Theme, motion and editor font size are in Settings. Reduced motion follows your system setting by default.</p>
    </>
  );
}

function About() {
  return (
    <>
      <h1>About the data</h1>
      <p class="lede">Everything is synthetic, generated in your browser. Nothing is real and nothing leaves your machine.</p>
      <ul>
        <li>
          <strong>Organisations</strong> are Microsoft's published fictitious companies (Contoso, Fabrikam, Northwind…). People are generated from common first and last
          names.
        </li>
        <li>
          <strong>External IP addresses</strong> come only from the documentation ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24; IPv6 2001:db8::/32);
          internal ones from private ranges (RFC 1918); autonomous-system numbers from the private range (RFC 6996).
        </li>
        <li>
          <strong>Attacker domains</strong> are generated per case and never point anywhere; <strong>hashes</strong> are random. None of them is an indicator of
          compromise — do not block them anywhere real.
        </li>
        <li>
          <strong>Threat actors</strong> are invented. Their behaviour is described at the level a defender sees in telemetry; tooling is summarised, never reproduced.
        </li>
        <li>
          <strong>Well-known services</strong> (Microsoft 365, a CDN, a code host) appear as the ordinary background they are in any company.
        </li>
      </ul>
      <p>
        Every case is checked automatically: its data stays inside these rules, and its reference investigation — run against a real SQLite database — surfaces every
        finding and indicator the grade expects.
      </p>
      <h2>Frameworks</h2>
      <p>
        Cases map to MITRE ATT&CK® ({MITRE_TECHNIQUES.length} techniques in the picker) and CompTIA CySA+ (CS0-003) domains: {CYSA_DOMAINS.map((d) => `${d.id} ${d.name}`).join(', ')}. ATT&CK® is a
        registered trademark of The MITRE Corporation; CySA+ is a trademark of CompTIA. This project is not affiliated with either.
      </p>
      <h2>Privacy</h2>
      <p>Your progress is stored in this browser's local storage. Export and import it from Settings. There is no account, no server and no tracking.</p>
      <h2>Built with</h2>
      <p class="small">Preact, CodeMirror, sql.js (SQLite compiled to WebAssembly), IBM Plex (SIL Open Font License), Vite.</p>
    </>
  );
}

export function Help({ section }: { section?: string }) {
  const cur = (SECTIONS.find(([id]) => id === section)?.[0] ?? 'start') as Section;
  return (
    <div class="page">
      <div class="help-layout">
        <nav class="help-nav" aria-label="Help sections">
          {SECTIONS.map(([id, label]) => (
            <a href={`#/help/${id}`} aria-current={cur === id ? 'page' : undefined}>
              {label}
            </a>
          ))}
        </nav>
        <article class="prose">
          {cur === 'start' && <Start />}
          {cur === 'kql' && <Kql />}
          {cur === 'reference' && <Reference />}
          {cur === 'tables' && <Tables />}
          {cur === 'grading' && <Grading />}
          {cur === 'keys' && <Keys />}
          {cur === 'about' && <About />}
        </article>
      </div>
    </div>
  );
}
