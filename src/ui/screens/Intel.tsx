import { profile, world } from '../store/app.ts';
import { Icon } from '../components/Icon.tsx';
import { Notice, Empty } from '../components/ui.tsx';
import { actorOf, campaignSummary } from '../../core/campaign/campaign.ts';
import { actorById } from '../../core/campaign/actors.ts';
import { WorldIndex } from '../../core/world/index.ts';
import { utcDateTime } from '../lib/format.ts';

const STAGE_LABEL: Record<string, string> = {
  'initial-access': 'Initial access',
  execution: 'Execution',
  persistence: 'Persistence',
  discovery: 'Discovery',
  lateral: 'Lateral movement',
  objective: 'Objective',
};

export function Intel() {
  const p = profile.value;
  const c = p.campaign;
  const w = world.value;

  return (
    <div class="page">
      <div class="page-head">
        <div>
          <p class="eyebrow">Threat intelligence</p>
          <h1>What IR knows</h1>
          <p>Only what your team has confirmed. An empty board can mean a quiet week — or that someone is working below your line of sight.</p>
        </div>
      </div>

      {!c ? (
        <div class="card">
          <Empty icon="globe">Nothing yet. The board fills as you work shifts: indicators you report, incidents you escalate, and anything IR can attribute.</Empty>
        </div>
      ) : (
        <CampaignBoard />
      )}

      <div class="grid grid-2" style={{ marginTop: 'var(--space-4)' }}>
        <section class="card" aria-labelledby="ti-h">
          <div class="card-head">
            <h2 id="ti-h">Indicators you reported</h2>
            <span class="badge">{c?.intel.length ?? 0}</span>
          </div>
          {!c || c.intel.length === 0 ? (
            <p class="muted small">Correct block indicators from your shifts land here — and in the ThreatIntel table the SIEM shows on your next shift.</p>
          ) : (
            <div class="table-wrap" tabIndex={0} role="region" aria-label="Indicators you reported">
              <table class="table">
                <caption class="visually-hidden">Indicators you reported</caption>
                <thead>
                  <tr>
                    <th scope="col">Indicator</th>
                    <th scope="col">Type</th>
                    <th scope="col">Shift</th>
                  </tr>
                </thead>
                <tbody>
                  {c.intel.map((i) => (
                    <tr>
                      <td class="mono small break">{i.indicator}</td>
                      <td class="small">{i.threat}</td>
                      <td class="mono small">{i.shift + 1}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <section class="card" aria-labelledby="ih-h">
          <div class="card-head">
            <h2 id="ih-h">Your incident history</h2>
            <span class="badge">{c?.history.length ?? 0}</span>
          </div>
          {!c || c.history.length === 0 ? (
            <p class="muted small">Every verdict you hand over appears here and in the SIEM's IncidentHistory table — including the ones you got wrong.</p>
          ) : (
            <div class="table-wrap" tabIndex={0} role="region" aria-label="Your incident history">
              <table class="table">
                <caption class="visually-hidden">Incidents you handled</caption>
                <thead>
                  <tr>
                    <th scope="col">When (UTC)</th>
                    <th scope="col">Alert</th>
                    <th scope="col">Your verdict</th>
                  </tr>
                </thead>
                <tbody>
                  {[...c.history]
                    .reverse()
                    .slice(0, 25)
                    .map((h) => (
                      <tr>
                        <td class="mono small nowrap">{utcDateTime(h.time).slice(0, 16)}</td>
                        <td class="small">{h.title}</td>
                        <td class="small">
                          {h.disposition} · {h.status}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      {p.campaignsFinished.length > 0 && (
        <section class="card" style={{ marginTop: 'var(--space-4)' }} aria-labelledby="past-h">
          <h2 id="past-h">Past campaigns</h2>
          <ul>
            {p.campaignsFinished.map((f) => (
              <li>
                {actorById(f.actorId)?.name ?? f.actorId} — <strong class={f.status === 'evicted' ? 'text-ok' : 'text-bad'}>{f.status === 'evicted' ? 'evicted' : 'breach'}</strong> after{' '}
                {f.shifts} stage{f.shifts === 1 ? '' : 's'}
              </li>
            ))}
          </ul>
        </section>
      )}
      <p class="faint small" style={{ marginTop: 'var(--space-4)' }}>
        Threat actors here are invented for training; any resemblance to real groups is coincidental. Victims are fictional staff of {w.org.name}.
      </p>
    </div>
  );
}

function CampaignBoard() {
  const c = profile.value.campaign!;
  const actor = actorOf(c);
  const sum = campaignSummary(c);
  const ended = c.status !== 'active';
  const idx = new WorldIndex(world.value);
  // Before the end, only contained stages are known to IR.
  const known = ended ? c.log : c.log.filter((e) => e.outcome === 'contained');
  const steps = actor.playbook.map((s) => s.stage);

  if (!ended && !c.identified) {
    return (
      <section class="card" aria-labelledby="camp-h">
        <h2 id="camp-h">
          <Icon name="globe" /> No attributed activity
        </h2>
        <p class="muted">
          IR has not attributed any intrusion to a known actor. {c.log.length > 0 ? 'Nothing you escalated so far was part of one — or nothing you escalated was caught in time to tell.' : ''}
        </p>
      </section>
    );
  }

  return (
    <section class={`card${ended ? '' : ' hero-card'}`} aria-labelledby="camp-h">
      <div class="card-head">
        <h2 id="camp-h">
          <Icon name="target" /> {actor.name}
        </h2>
        <span class={`badge ${c.status === 'evicted' ? 'badge-ok' : c.status === 'breached' ? 'badge-bad' : 'badge-warn'}`}>{c.status === 'active' ? 'active' : c.status === 'evicted' ? 'evicted' : 'breach'}</span>
      </div>
      <p>
        <strong>{actor.motivation}.</strong> {actor.blurb}
      </p>
      {ended && (
        <Notice tone={c.status === 'evicted' ? 'ok' : 'bad'}>
          <p>{c.log.at(-1)?.narrative}</p>
          <p class="small">The next shift starts a new campaign — a different actor, unannounced.</p>
        </Notice>
      )}
      <h3 class="section-label">Kill chain {ended ? '' : '(known so far)'}</h3>
      <ol class="killchain" style={{ '--steps': steps.length }} aria-label="Campaign stages">
        {steps.map((st, i) => {
          const entries = known.filter((e) => e.stage === st);
          const contained = entries.some((e) => e.outcome === 'contained');
          const reached = ended && c.log.some((e) => e.stage === st && e.outcome !== 'contained');
          return (
            <li class={contained ? 'is-contained' : reached ? 'is-done' : !ended && i === c.stage && c.identified ? 'is-current' : ''} aria-label={`${STAGE_LABEL[st]}: ${contained ? 'contained' : reached ? 'actor succeeded' : 'no known activity'}`}>
              {STAGE_LABEL[st]}
            </li>
          );
        })}
      </ol>
      <p class="faint small">
        Containments: {sum.contained}
        {ended ? ` · intrusions attempted: ${c.intrusions}` : ''}
      </p>
      <h3 class="section-label">Timeline</h3>
      <ol class="timeline">
        {known.map((e) => (
          <li class={e.outcome === 'contained' ? 'tl-ok' : e.outcome === 'flagged' ? 'tl-warn' : 'tl-bad'}>
            <strong>
              Shift {e.shift + 1} · {STAGE_LABEL[e.stage]} — {e.outcome}
            </strong>
            <p class="small muted">{e.narrative}</p>
            <p class="faint small mono">
              {idx.personByUpn(e.victim)?.display ?? e.victim} · {e.host}
              {e.blocked.length ? ` · blocked ${e.blocked.join(', ')}` : ''}
            </p>
          </li>
        ))}
      </ol>
    </section>
  );
}
