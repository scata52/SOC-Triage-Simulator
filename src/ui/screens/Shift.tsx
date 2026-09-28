import { useEffect, useRef, useState } from 'preact/hooks';
import { signal } from '@preact/signals';
import { profile, update, world, today, toast, announce } from '../store/app.ts';
import { navigate } from '../router.ts';
import { siem } from '../lib/siem.ts';
import type { OpenSpec, SessionInfo } from '../lib/protocol.ts';
import { clock, duration, plural, utcTime } from '../lib/format.ts';
import { play } from '../lib/sound.ts';
import { emptyVerdict, DISPOSITION_LABELS, type Verdict } from '../../core/grading/grade.ts';
import { scoreShift, type ShiftResult } from '../../core/shift/score.ts';
import { recordShift, actorOf, type CampaignEntry } from '../../core/campaign/campaign.ts';
import { finishShift, recordAttempt, recentShiftTemplates, updateShift, nextShiftNumber } from '../../state/profile.ts';
import { Workspace } from '../components/Workspace.tsx';
import { Debrief } from '../components/Debrief.tsx';
import { Icon } from '../components/Icon.tsx';
import { Loading, Notice, Ring, Sev, Dialog } from '../components/ui.tsx';
import { BudgetPicker, beginShift } from './Home.tsx';
import type { Budget } from '../../core/shift/plan.ts';

// The open spec is fixed at shift start so the same scenario can be rebuilt
// after a reload (the campaign state changes only at handover).
function specFor(): OpenSpec | null {
  const p = profile.peek();
  const s = p.activeShift;
  if (!s) return null;
  return { kind: 'shift', worldSeed: p.worldSeed, number: s.number, budget: s.budget, campaign: p.campaign, recent: recentShiftTemplates(p) };
}

const shiftSession = signal<SessionInfo | null>(null);
let sessionFor: string | null = null;

// Always (re)open on mount: the worker holds one session at a time, and a
// practice case opened mid-shift replaces it. Reopening an already-open
// session is a no-op in the worker; the cached info avoids a loading flash.
function useShiftSession(): { session: SessionInfo | null; error: string | null } {
  const [error, setError] = useState<string | null>(null);
  const [ready, setReady] = useState(false);
  const s = profile.value.activeShift;
  const key = s ? `${profile.value.worldSeed}:${s.number}` : null;
  useEffect(() => {
    if (!key) return;
    const spec = specFor();
    if (!spec) return;
    let live = true;
    setReady(false);
    if (sessionFor !== key) shiftSession.value = null;
    siem
      .open(spec)
      .then((info) => {
        if (!live) return;
        sessionFor = key;
        shiftSession.value = info;
        setReady(true);
        if (info.plan?.campaignAlertId && !profile.peek().activeShift?.campaignAlertId) {
          update((p) => (p.activeShift ? { ...p, activeShift: { ...p.activeShift, campaignAlertId: info.plan!.campaignAlertId } } : p));
        }
      })
      .catch((e: Error) => live && setError(e.message));
    return () => {
      live = false;
    };
  }, [key]);
  // Show the cached queue immediately, but only let queries run once the
  // worker has this session open again.
  return { session: sessionFor === key && (ready || !!shiftSession.value) ? shiftSession.value : null, error };
}

// The shift clock runs only while a shift page is open and visible. It ticks
// in its own signal (only the readout re-renders) and is persisted to the
// profile every 15 s, on submit and when the page is hidden.
const elapsed = signal(0);
let clockNumber: number | null = null;

function persistClock(): void {
  if (profile.peek().activeShift && clockNumber === profile.peek().activeShift!.number) update((p) => updateShift(p, { elapsedSec: elapsed.peek() }));
}

function useClock(onExpire: () => void): void {
  const s = profile.value.activeShift;
  const expired = useRef(false);
  if (s && clockNumber !== s.number) {
    clockNumber = s.number;
    elapsed.value = s.elapsedSec;
  }
  useEffect(() => {
    const onHide = () => document.visibilityState === 'hidden' && persistClock();
    document.addEventListener('visibilitychange', onHide);
    const t = setInterval(() => {
      const cur = profile.peek().activeShift;
      if (!cur || document.visibilityState !== 'visible') return;
      elapsed.value += 1;
      if (elapsed.value % 15 === 0) persistClock();
      if (cur.budget > 0) {
        const left = cur.budget * 60 - elapsed.value;
        if (left === 60) {
          play('alert');
          announce('One minute left on the shift clock.');
          toast('One minute left.');
        }
        if (left <= 0 && !expired.current) {
          expired.current = true;
          onExpire();
        }
      }
    }, 1000);
    return () => {
      clearInterval(t);
      document.removeEventListener('visibilitychange', onHide);
      persistClock();
    };
  }, []);
}

function ClockChip() {
  const s = profile.peek().activeShift;
  const left = s && s.budget > 0 ? s.budget * 60 - elapsed.value : null;
  return (
    <span class={`chip chip-mono${left !== null && left < 120 ? ' text-bad' : ''}`} role="timer" aria-label={left !== null ? `${clock(left)} left on the shift` : `${clock(elapsed.value)} elapsed`}>
      <Icon name="clock" /> {left !== null ? clock(left) : clock(elapsed.value)}
    </span>
  );
}

function BigClock() {
  const s = profile.peek().activeShift;
  const left = s && s.budget > 0 ? s.budget * 60 - elapsed.value : null;
  return (
    <div class="stat">
      <span class={`shift-clock${left !== null && left < 120 ? ' is-low' : ''}`} role="timer" aria-live="off">
        {left !== null ? clock(left) : clock(elapsed.value)}
      </span>
      <span class="stat-label">{left !== null ? 'left on the clock' : 'elapsed (untimed)'}</span>
    </div>
  );
}

interface HandoverRecord {
  number: number;
  spec: OpenSpec;
  result: ShiftResult;
  campaign?: CampaignEntry;
  actorName?: string;
  identified: boolean;
  elapsedSec: number;
  budget: Budget;
  timeUp: boolean;
}

const HANDOVER_KEY = 'soc-last-handover';
function saveHandover(h: HandoverRecord): void {
  try {
    sessionStorage.setItem(HANDOVER_KEY, JSON.stringify(h));
  } catch {
    /* too large or unavailable — the handover screen falls back to the summary */
  }
}
function loadHandover(): HandoverRecord | null {
  try {
    const raw = sessionStorage.getItem(HANDOVER_KEY);
    return raw ? (JSON.parse(raw) as HandoverRecord) : null;
  } catch {
    return null;
  }
}
const lastHandover = signal<HandoverRecord | null>(null);

function handOver(session: SessionInfo, timeUp = false): void {
  persistClock();
  const p = profile.peek();
  const s = p.activeShift;
  if (!s) return;
  const spec = specFor()!;
  const result = scoreShift(session.cases, s.submissions);
  const w = world.peek();
  const day = today();
  const now = Date.now();
  let next = p;
  for (const r of result.cases) {
    if (!r.handled) continue;
    next = recordAttempt(next, { c: r.case, grade: r.grade, verdict: r.verdict, mode: r.alertId === s.campaignAlertId ? 'campaign' : 'shift', now, day, durationSec: null, id: `shift-${s.number}/${r.alertId}` }).profile;
  }
  const campaign = p.campaign ? recordShift(p.campaign, w, s.number, session.infra, result, s.campaignAlertId) : null;
  const entry = campaign && campaign.log.length > (p.campaign?.log.length ?? 0) ? campaign.log[campaign.log.length - 1] : undefined;
  next = finishShift(next, result, { now, campaign, campaignOutcome: entry?.outcome });
  const h: HandoverRecord = {
    number: s.number,
    spec,
    result,
    campaign: entry,
    actorName: campaign ? actorOf(campaign).name : undefined,
    identified: !!campaign?.identified,
    elapsedSec: s.elapsedSec,
    budget: s.budget,
    timeUp,
  };
  update(() => next);
  lastHandover.value = h;
  saveHandover(h);
  play(result.clean ? 'good' : 'alert');
  navigate({ name: 'handover' });
}

function statusOf(alertId: string): { label: string; tone: string; verdict?: Verdict } {
  const s = profile.value.activeShift;
  if (!s) return { label: '', tone: '' };
  const sub = [...s.submissions].reverse().find((x) => x.alertId === alertId);
  if (sub) return { label: sub.verdict.disposition ? DISPOSITION_LABELS[sub.verdict.disposition] : 'submitted', tone: 'badge-ok', verdict: sub.verdict };
  const d = s.drafts[alertId];
  if (d && (d.pins.length || d.disposition || d.notes || d.indicators.length)) return { label: 'in progress', tone: 'badge-warn' };
  return { label: 'new', tone: 'badge-accent' };
}

function NoShift() {
  const p = profile.value;
  const [budget, setBudget] = useState<Budget>(p.settings.defaultBudget);
  const last = p.shifts.at(-1);
  return (
    <div class="page page-narrow">
      <div class="page-head">
        <div>
          <p class="eyebrow">Shift {nextShiftNumber(p) + 1}</p>
          <h1>No shift in progress</h1>
          <p>Six to nine alerts, one set of logs, and a clock. Prioritise: the real incidents are worth more, and they are worth more the sooner you get to them.</p>
        </div>
      </div>
      <div class="card">
        <BudgetPicker value={budget} onChange={setBudget} />
        <div class="btn-row" style={{ marginTop: 'var(--space-4)' }}>
          <button type="button" class="btn btn-primary btn-lg" onClick={() => beginShift(budget)}>
            Start shift <Icon name="right" />
          </button>
          {last && (
            <a class="btn btn-ghost" href="#/handover">
              Last handover (score {last.score})
            </a>
          )}
        </div>
      </div>
    </div>
  );
}

export function ShiftScreen({ alertId }: { alertId?: string }) {
  const p = profile.value;
  const s = p.activeShift;
  const { session, error } = useShiftSession();
  const [confirmOpen, setConfirmOpen] = useState(false);
  const sessionRef = useRef(session);
  sessionRef.current = session;
  useClock(() => {
    if (sessionRef.current) {
      toast("Time's up — handing over.");
      handOver(sessionRef.current, true);
    }
  });

  if (!s) return <NoShift />;
  if (error)
    return (
      <div class="page page-narrow">
        <Notice tone="bad">
          <p>The shift could not be built: {error}</p>
        </Notice>
      </div>
    );
  if (!session) return <Loading text="Pulling the queue and a day of logs…" />;

  const clockEl = <ClockChip />;

  if (alertId) {
    const c = session.cases.find((x) => x.alertId === alertId);
    if (!c) {
      return (
        <div class="page page-narrow">
          <h1>No alert {alertId} in this shift</h1>
          <a href="#/shift">Back to the queue</a>
        </div>
      );
    }
    const draft = s.drafts[alertId] ?? emptyVerdict();
    const submitted = s.submissions.some((x) => x.alertId === alertId);
    return (
      <Workspace
        key={alertId}
        session={session}
        c={c}
        draft={draft}
        onDraft={(v) => update((x) => (x.activeShift ? updateShift(x, { drafts: { ...x.activeShift.drafts, [alertId]: v } }) : x))}
        onSubmit={() => {
          update((x) => (x.activeShift ? updateShift(x, { elapsedSec: elapsed.peek(), submissions: [...x.activeShift.submissions, { alertId, verdict: x.activeShift.drafts[alertId] ?? draft, atSec: elapsed.peek() }] }) : x));
          play('submit');
          toast(`${alertId} ${submitted ? 'updated' : 'submitted'}. Back to the queue.`);
          navigate({ name: 'shift' });
        }}
        submitLabel={submitted ? 'Update verdict' : 'Submit & back to queue'}
        storageKey={`shift-${s.number}-${alertId}`}
        toolbar={
          <div class="ws-title">
            <a class="btn btn-ghost btn-sm" href="#/shift">
              <Icon name="left" /> Queue
            </a>
            <span class="mono faint">{alertId}</span>
            <h1 class="ws-h1">{c.alert.rule}</h1>
            {submitted && <span class="badge badge-ok">submitted</span>}
            {clockEl}
          </div>
        }
      />
    );
  }

  const handled = new Set(s.submissions.map((x) => x.alertId)).size;
  return (
    <div class="page">
      <div class="shift-head">
        <div>
          <p class="eyebrow">
            {world.value.org.name} · shift {s.number + 1}
          </p>
          <h1 style={{ margin: 0 }}>Alert queue</h1>
        </div>
        <span class="spacer" />
        <BigClock />
        <div class="stat">
          <span class="stat-value">
            {handled}/{session.cases.length}
          </span>
          <span class="stat-label">handled</span>
        </div>
        <button type="button" class="btn btn-primary" onClick={() => (handled < session.cases.length ? setConfirmOpen(true) : handOver(session))}>
          <Icon name="hand" /> Hand over
        </button>
      </div>
      <p class="muted small">
        Times are UTC; logs run to <span class="mono">{utcTime(session.now)}</span>. The tool's severity is its opinion, not a fact. Open an alert, investigate,
        submit — you can revise a verdict until you hand over.
      </p>
      <ul class="queue" aria-label="Alerts in the queue">
        {session.cases.map((c) => {
          const st = statusOf(c.alertId);
          return (
            <li>
              <a class={`queue-item sev-${c.alert.severity}${st.verdict ? ' is-done' : ''}`} href={`#/shift/${c.alertId}`}>
                <span class="mono">{c.alertId}</span>
                <span class="mono faint queue-time">{utcTime(c.alert.time)}</span>
                <span class="queue-rule">
                  {c.alert.rule}
                  <small>{c.alert.product}</small>
                </span>
                <span class="row">
                  <Sev s={c.alert.severity} />
                  <span class={`badge ${st.tone}`}>{st.label}</span>
                </span>
              </a>
            </li>
          );
        })}
      </ul>
      <Dialog
        open={confirmOpen}
        title="Hand over with alerts unworked?"
        onClose={() => setConfirmOpen(false)}
        footer={
          <>
            <button type="button" class="btn" onClick={() => setConfirmOpen(false)}>
              Keep working
            </button>
            <button type="button" class="btn btn-primary" onClick={() => (setConfirmOpen(false), handOver(session))}>
              Hand over now
            </button>
          </>
        }
      >
        <p>
          {plural(session.cases.length - handled, 'alert')} will be left in the queue and score zero. If one of them was the real incident, the next shift inherits
          the consequences.
        </p>
      </Dialog>
    </div>
  );
}

export function HandoverScreen() {
  const h = lastHandover.value ?? loadHandover();
  const [review, setReview] = useState<string | null>(null);
  const [ready, setReady] = useState(false);
  const p = profile.value;

  useEffect(() => {
    if (!h) return;
    lastHandover.value = h;
    siem.open(h.spec).then(() => setReady(true));
  }, [h?.number]);

  if (!h) {
    const last = p.shifts.at(-1);
    return (
      <div class="page page-narrow">
        <h1>Handover</h1>
        {last ? (
          <p>
            Shift {last.number + 1}: score {last.score}, {last.handled}/{last.total} handled, {plural(last.missedIncidents, 'missed incident')}. The detailed report is
            only kept for the browser session.
          </p>
        ) : (
          <p>No shift has been handed over yet.</p>
        )}
        <a class="btn btn-primary" href="#/shift">
          Go to shift
        </a>
      </div>
    );
  }

  const r = h.result;
  if (review) {
    const cr = r.cases.find((x) => x.alertId === review)!;
    return (
      <div class="page">
        {!ready ? (
          <Loading text="Reloading the shift's logs…" />
        ) : (
          <Debrief
            c={cr.case}
            grade={cr.grade}
            verdict={cr.verdict}
            actions={
              <button type="button" class="btn" onClick={() => setReview(null)}>
                <Icon name="left" /> Back to the handover
              </button>
            }
          />
        )}
      </div>
    );
  }

  const order = new Map(r.cases.filter((x) => x.order !== null).map((x) => [x.alertId, x.order! + 1]));
  const ideal = new Map(r.idealOrder.map((id, i) => [id, i + 1]));
  const outcomeTone = h.campaign?.outcome === 'contained' ? 'ok' : h.campaign ? 'bad' : undefined;
  return (
    <div class="page">
      <div class="debrief">
        <section class="card debrief-hero" aria-labelledby="ho-h">
          <Ring value={r.score / 100} label={`${r.score}`} sub="/ 100" color={r.score >= 80 ? 'var(--ok)' : r.score >= 55 ? 'var(--warn)' : 'var(--bad)'} />
          <div class="debrief-hero-text">
            <p class="eyebrow">Shift {h.number + 1} handover</p>
            <h1 id="ho-h">{r.clean ? 'Clean shift.' : r.missedIncidents.length ? `${plural(r.missedIncidents.length, 'real incident')} slipped through.` : 'Shift complete.'}</h1>
            <p>
              Verdict quality {r.caseScore}% · prioritisation {Math.round(r.prioritisation * 100)}% · {r.handled}/{r.total} handled in {duration(h.elapsedSec)}
              {h.timeUp ? ' (clock ran out)' : ''} · +{r.xp} XP{r.clean ? ' incl. clean-shift bonus' : ''}
            </p>
            <div class="btn-row">
              <button type="button" class="btn btn-primary" onClick={() => beginShift(p.settings.defaultBudget)}>
                Next shift <Icon name="right" />
              </button>
              <a class="btn" href="#/intel">
                <Icon name="globe" /> Threat intel
              </a>
              <a class="btn btn-ghost" href="#/">
                Console
              </a>
            </div>
          </div>
        </section>

        {h.campaign && (
          <Notice tone={outcomeTone as 'ok' | 'bad'} icon={h.campaign.outcome === 'contained' ? 'shield' : 'alert'}>
            <p>
              <strong>{h.campaign.outcome === 'contained' ? 'Contained.' : h.campaign.outcome === 'flagged' ? 'Flagged, not contained.' : 'Missed.'}</strong>{' '}
              {h.campaign.alertId} was {h.identified ? `part of an intrusion by ${h.actorName}` : 'part of an ongoing intrusion'}. {h.campaign.narrative}
            </p>
          </Notice>
        )}

        <section class="card" aria-labelledby="ho-cases">
          <h2 id="ho-cases">Alert by alert</h2>
          <div class="table-wrap" tabIndex={0} role="region" aria-label="Alerts in this shift">
            <table class="table">
              <caption class="visually-hidden">Your verdict, the truth, points and handling order for each alert</caption>
              <thead>
                <tr>
                  <th scope="col">Alert</th>
                  <th scope="col">It was</th>
                  <th scope="col">Your call</th>
                  <th scope="col" class="num">
                    Score
                  </th>
                  <th scope="col" class="num">
                    Order (ideal)
                  </th>
                  <th scope="col">
                    <span class="visually-hidden">Review</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {r.cases.map((x) => {
                  const missed = r.missedIncidents.includes(x.alertId);
                  const falseEsc = r.falseEscalations.includes(x.alertId);
                  return (
                    <tr>
                      <th scope="row" style={{ textTransform: 'none', letterSpacing: 0, fontWeight: 500, color: 'var(--text)' }}>
                        <span class="mono faint">{x.alertId}</span> {x.case.alert.rule}
                      </th>
                      <td class="small">
                        {x.case.lesson}{' '}
                        {x.case.truth.disposition === 'true-positive' && <span class="badge badge-bad">incident</span>}
                        {x.alertId === h.campaign?.alertId && <span class="badge badge-warn">campaign</span>}
                      </td>
                      <td class="small">
                        {x.handled ? (x.verdict.disposition ? DISPOSITION_LABELS[x.verdict.disposition] : '—') : <span class="text-bad">unworked</span>}
                        {missed && <span class="badge badge-bad"> missed</span>}
                        {falseEsc && <span class="badge badge-warn"> false escalation</span>}
                      </td>
                      <td class="num mono">{x.grade.percent}</td>
                      <td class="num mono">
                        {order.get(x.alertId) ?? '—'} ({ideal.get(x.alertId)})
                      </td>
                      <td>
                        <button type="button" class="btn btn-sm btn-ghost" onClick={() => setReview(x.alertId)} aria-label={`Review ${x.alertId}`}>
                          Review
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <p class="faint small">
            Ideal order ranks real, escalation-worthy incidents by severity first. Prioritisation measures how close your order came (nDCG): an incident you reach late
            costs less than one you never reach.
          </p>
        </section>
      </div>
    </div>
  );
}
