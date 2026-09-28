// Lateral movement, privilege escalation, exfiltration and ransomware.
// Destructive or credential-theft steps are represented the way a defender
// sees them in telemetry — process, parent, host, account and a summarised
// argument string — rather than as reproducible commands.
import type { CaseTemplate } from '../model.ts';
import type { RowRef } from '../../logs/corpus.ts';
import { DAY, HOUR, MIN, SEC, atLocalHour } from '../../logs/time.ts';
import { BIN, binaryHash } from '../../synth/software.ts';
import { domain, host, ip, kdt, rubric, sha, technique, user } from './util.ts';

// ---------------------------------------------------------------------------
// PsExec from a user laptop to a domain controller (TRUE POSITIVE, critical)
// ---------------------------------------------------------------------------
const lateralPsExec: CaseTemplate = {
  id: 'impact-lateral-psexec',
  category: 'lateral',
  difficulty: 'tier3',
  title: 'PsExec from a user workstation to a domain controller',
  cysaDomains: ['1.0', '3.0'],
  kind: 'incident',
  twin: 'endpoint-benign-admin-psexec',
  stages: ['lateral'],
  when: 'any',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const ad = world.org.netbios;
    const victim = ctx.foothold?.personId ?