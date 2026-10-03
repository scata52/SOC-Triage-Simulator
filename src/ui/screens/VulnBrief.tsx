// The brief of a vulnerability case: briefing, attachments and revealed hints.
// Typed to VulnCaseView, so nothing from the answer key can reach it.

import { TABLE_NAMES } from '../../core/logs/schema.ts';
import { HINT_PENALTY } from '../../core/grading/grade.ts';
import type { VulnCaseView } from '../../core/vuln/worklist.ts';
import { Icon } from '../components/Icon.tsx';
import { utcDateTime } from '../lib/format.ts';

// A hint that contains a query: from the first table name to the end.
function hintQuery(h: string): { lead: string; kql: string } | null {
  const m = new RegExp(`\\b(${TABLE_NAMES.join('|')})\\b\\s*(\\n\\s*)?\\|`).exec(h);
  if (!m) return null;
  return { lead: h.slice(0, m.index).trim(), kql: h.slice(m.index).trim() };
}

export function VulnBrief({
  view,
  hintsUsed,
  narrow,
  onRevealHint,
  onLoadQuery,
}: {
  view: VulnCaseView;
  hintsUsed: number;
  narrow: boolean;
  onRevealHint: () => void;
  onLoadQuery: (kql: string) => void;
}) {
  return (
    <div class="vc-brief-body">
      <h2 class="section-label" id="vc-brief-h">
        Brief
      </h2>
      <p class="faint small mono">Scan review as of {utcDateTime(view.now)}</p>
      <p class="small">{view.briefing}</p>

      {view.attachments.map((att) => (
        <details class="disclosure attachment" open={!narrow}>
          <summary>
            <Icon name="book" /> {att.title}
          </summary>
          <div class="disclosure-body">
            {typeof att.body === 'string' ? (
              <pre class={`attachment-body mono${att.kind === 'email' ? ' is-email' : ''}`}>{att.body}</pre>
            ) : (
              <dl class="kv">
                {att.body.map(([k, v]) => (
                  <>
                    <dt>{k}</dt>
                    <dd>{v}</dd>
                  </>
                ))}
              </dl>
            )}
            {att.caption && <p class="faint small">{att.caption}</p>}
          </div>
        </details>
      ))}

      <section aria-labelledby="vc-hints-h" class="hints">
        <h3 class="section-label" id="vc-hints-h">
          Hints
        </h3>
        {view.hints.slice(0, hintsUsed).map((h, i) => {
          const q = hintQuery(h);
          return (
            <div class="hint" id={`vc-hint-${i}`} tabIndex={-1}>
              <span class="hint-n mono">{i + 1}</span>
              <div>
                {q ? (
                  <>
                    {q.lead && <p class="small">{q.lead}</p>}
                    <pre class="code-block mono">{q.kql}</pre>
                    <button type="button" class="btn btn-sm" onClick={() => onLoadQuery(q.kql)}>
                      <Icon name="terminal" /> Load into editor
                    </button>
                  </>
                ) : (
                  <p class="small">{h}</p>
                )}
              </div>
            </div>
          );
        })}
        {hintsUsed < view.hints.length ? (
          <button type="button" class="btn btn-sm btn-ghost" onClick={onRevealHint}>
            <Icon name="bulb" /> Reveal hint {hintsUsed + 1} of {view.hints.length}
            <span class="faint"> (−{Math.round(HINT_PENALTY * 100)}% of the evidence score)</span>
          </button>
        ) : (
          <p class="faint small">No more hints.</p>
        )}
      </section>
    </div>
  );
}
