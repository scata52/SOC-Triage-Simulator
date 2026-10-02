import { useEffect, useRef, useState } from 'preact/hooks';
import { profile, update, today, announce, toast } from '../store/app.ts';
import { navigate } from '../router.ts';
import { siem } from '../lib/siem.ts';
import type { SessionInfo } from '../lib/protocol.ts';
import { alertType, dailyCase, DAILY_WORLD, resolveCase, studyRoute, ALERT_TYPES } from '../lib/cases.ts';
import { clock, dailySeed, randomSeed } from '../lib/format.ts';
import { play } from '../lib/sound.ts';
import { emptyVerdict, gradeCase, type CaseGrade, type Verdict } from '../../core/grading/grade.ts';
import { recordAttempt, asStudyAttempts } from '../../state/profile.ts';
import { FULL_STUDY_POOL, nextStudyCase } from '../../core/study/scheduler.ts';
import { createRng } from '../../core/rng.ts';
import { Workspace } from '../components/Workspace.tsx';
import { Debrief } from '../components/Debrief.tsx';
import { Icon } from '../components/Icon.tsx';
import { Loading, Notice } from '../components/ui.tsx';
import { focusHeading } from '../lib/focus.ts';

type Mode = 'practice' | 'study' | 'daily';

function draftKey(k: string): string {
  return `draft:${k}`;
}
function loadDraft(k: string): Verdict {
  try {
    const raw = sessionStorage.getItem(draftKey(k));
    return raw ? { ...emptyVerdict(), ...(JSON.parse(raw) as Verdict) } : emptyVerdict();
  } catch {
    return emptyVerdict();
  }
}
function saveDraft(k: string, v: Verdict | null): void {
  try {
    if (v) sessionStorage.setItem(draftKey(k), JSON.stringify(v));
    else sessionStorage.removeItem(draftKey(k));
  } catch {
    /* ignore */
  }
}

function Timer({ since }: { since: number }) {
  const [, tick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => tick((x) => x + 1), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <span class="chip chip-mono" aria-label="Time on this case" role="timer">
      <Icon name="clock" /> {clock((Date.now() - since) / 1000)}
    </span>
  );
}

export function nextStudyRoute(exclude: string[] = []): void {
  const p = profile.peek();
  const s = nextStudyCase(p.cards, asStudyAttempts(p), today(), createRng(`study:${Date.now()}`), { exclude, pool: FULL_STUDY_POOL });
  navigate(studyRoute(s.templateId, randomSeed()));
}

export function CaseScreen({ slug, seed, mode }: { slug: string; seed: string; mode: Mode }) {
  const template = resolveCase(slug, seed);
  const type = alertType(slug);
  const worldSeed = mode === 'daily' ? DAILY_WORLD : profile.value.worldSeed;
  const key = `${mode}:${worldSeed}:${slug}:${seed}`;
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  const [draft, setDraft] = useState<Verdict>(() => loadDraft(key));
  const [done, setDone] = useState<{ grade: CaseGrade; verdict: Verdict } | null>(null);
  const started = useRef(Date.now());

  useEffect(() => {
    if (!template) return;
    let live = true;
    siem
      .open({ kind: 'practice', worldSeed, templateId: template.id, seed })
      .then((s) => live && setSession(s))
      .catch((e: Error) => live && setFailed(e.message));
    return () => {
      live = false;
    };
  }, [key]);

  useEffect(() => {
    if (session) focusHeading();
  }, [session, done]);

  if (!template || !type) {
    return (
      <div class="page page-narrow">
        <h1>Unknown case</h1>
        <p>
          There is no alert type called <code>{slug}</code>. <a href="#/practice">Browse the library</a>.
        </p>
      </div>
    );
  }
  if (failed) {
    return (
      <div class="page page-narrow">
        <h1>The case could not be built</h1>
        <Notice tone="bad">
          <p>{failed}</p>
        </Notice>
      </div>
    );
  }
  if (!session) return <Loading text="Generating a day of logs…" />;
  const c = session.cases[0];

  const onDraft = (v: Verdict) => {
    setDraft(v);
    saveDraft(key, v);
  };

  const submit = () => {
    const grade = gradeCase(c, draft);
    const daily = mode === 'daily' ? dailySeed() : undefined;
    update((p) => recordAttempt(p, { c, grade, verdict: draft, mode: mode === 'study' ? 'study' : 'practice', now: Date.now(), day: today(), durationSec: Math.round((Date.now() - started.current) / 1000), dailySeed: daily }).profile);
    saveDraft(key, null);
    setDone({ grade, verdict: draft });
    play(grade.dispositionCorrect ? 'good' : 'bad');
    announce(`Scored ${grade.percent} out of 100. ${grade.dispositionCorrect ? 'Right call.' : 'Wrong call.'}`);
    window.scrollTo({ top: 0 });
  };

  if (done) {
    const retry = () => {
      setDraft(emptyVerdict());
      setDone(null);
      started.current = Date.now();
    };
    return (
      <div class="page">
        <Debrief
          c={c}
          grade={done.grade}
          verdict={done.verdict}
          actions={
            <>
              {mode === 'study' ? (
                <button type="button" class="btn btn-primary" onClick={() => nextStudyRoute([c.templateId])}>
                  Next study case <Icon name="right" />
                </button>
              ) : mode === 'daily' ? (
                <a class="btn btn-primary" href="#/">
                  Back to console
                </a>
              ) : (
                <button
                  type="button"
                  class="btn btn-primary"
                  onClick={() => {
                    const pool = ALERT_TYPES.filter((a) => !a.hunt && a.slug !== slug);
                    navigate({ name: 'case', slug: pool[Math.floor(Math.random() * pool.length)].slug, seed: randomSeed() });
                  }}
                >
                  Next case <Icon name="right" />
                </button>
              )}
              <button type="button" class="btn" onClick={retry}>
                <Icon name="history" /> Work it again
              </button>
              <button type="button" class="btn btn-ghost" onClick={() => navigate({ name: 'case', slug, seed: randomSeed(), study: mode === 'study' })}>
                Same alert, new variation
              </button>
            </>
          }
        />
      </div>
    );
  }

  const toolbar = (
    <div class="ws-title">
      <a class="btn btn-ghost btn-sm" href={mode === 'study' ? '#/study' : mode === 'daily' ? '#/' : '#/practice'}>
        <Icon name="left" /> {mode === 'study' ? 'Study' : mode === 'daily' ? 'Console' : 'Library'}
      </a>
      <h1 class="ws-h1">{type.title}</h1>
      {mode === 'daily' && <span class="badge badge-accent">case of the day</span>}
      {mode === 'study' && <span class="badge badge-accent">study</span>}
      {profile.value.settings.timerEnabled && <Timer since={started.current} />}
    </div>
  );

  return (
    <Workspace
      session={session}
      c={c}
      draft={draft}
      onDraft={onDraft}
      onSubmit={() => {
        if (!draft.pins.length && !confirm('You have not pinned any evidence. Submit anyway?')) return;
        submit();
      }}
      submitLabel="Submit verdict"
      toolbar={toolbar}
      storageKey={key.replace(/[^\w-]/g, '_')}
    />
  );
}

export function DailyScreen() {
  const d = dailyCase(dailySeed());
  useEffect(() => {
    if (profile.peek().dailyDone.includes(d.seed)) toast("You've done today's case — this one won't count twice.");
  }, []);
  return <CaseScreen slug={d.slug} seed={d.seed} mode="daily" key={`daily-${d.seed}`} />;
}
