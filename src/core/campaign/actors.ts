// Fictional threat actors. The names are coined words, chosen NOT to follow
// any threat-intelligence vendor's naming scheme (animal suffixes, weather
// words, metals and colours, APT/TA numbers) so they cannot be mistaken for
// a real group. tests/campaign.test.ts enforces that.

import type { CampaignStage } from '../cases/model.ts';
import type { Department, Person } from '../world/world.ts';

export interface ActorStep {
  stage: CampaignStage;
  templates: string[];
  // What the actor did next if this step went unnoticed / was contained.
  missed: string;
  contained: string;
}

export interface Actor {
  id: string;
  name: string;
  motivation: string;
  blurb: string;
  // Containments it takes before the actor gives up on the organisation.
  tenacity: number;
  victimDepartments: Department[];
  playbook: ActorStep[];
  objective: string;
}

export const ACTORS: Actor[] = [
  {
    id: 'orrax',
    name: 'Orrax',
    motivation: 'Financially motivated — data-encryption extortion',
    blurb: 'Buys or phishes its way into mid-sized firms, lives off the land for a few days, then encrypts file servers overnight.',
    tenacity: 2,
    victimDepartments: ['Finance', 'Sales', 'Operations', 'Marketing'],
    objective: 'encrypted the file server overnight',
    playbook: [
      { stage: 'initial-access', templates: ['email-phish-attachment', 'email-phish-credential'], missed: 'The lure worked and nobody pulled the thread: {actor} now has a foothold on {host}.', contained: 'IR isolated {host} and reset {victim}’s credentials before the operator could settle in.' },
      { stage: 'execution', templates: ['endpoint-encoded-powershell', 'network-c2-beacon'], missed: 'The implant on {host} kept calling home. The operator had time to make it stick.', contained: 'IR reimaged {host}; the implant died with it.' },
      { stage: 'persistence', templates: ['endpoint-scheduled-task'], missed: 'A scheduled task now brings the implant back after every reboot of {host}.', contained: 'The persistence was removed and {host} rebuilt.' },
      { stage: 'discovery', templates: ['network-internal-portscan'], missed: 'The operator mapped the server subnet from {host} and found the file servers.', contained: 'IR cut the operator off mid-reconnaissance.' },
      { stage: 'lateral', templates: ['impact-lateral-psexec'], missed: 'With a stolen admin credential the operator reached a domain controller. Encryption is now one step away.', contained: 'The stolen admin account was disabled and the domain controllers checked; the operator lost its keys.' },
      { stage: 'objective', templates: ['impact-ransomware'], missed: '{actor} encrypted a file server. Recovery is now a business-continuity problem.', contained: 'The encryption was stopped early and the share restored from backup.' },
    ],
  },
  {
    id: 'velmyr',
    name: 'Velmyr',
    motivation: 'Espionage — theft of commercial data',
    blurb: 'Patient and quiet: takes over cloud identities, then moves to an endpoint and smuggles data out over DNS.',
    tenacity: 3,
    victimDepartments: ['Finance', 'Sales', 'Operations'],
    objective: 'exfiltrated commercial data over DNS',
    playbook: [
      { stage: 'initial-access', templates: ['identity-mfa-fatigue', 'identity-password-spray'], missed: '{actor} is inside {victim}’s mailbox and nobody knows.', contained: 'IR revoked {victim}’s sessions, reset the password and tightened MFA.' },
      { stage: 'execution', templates: ['identity-impossible-travel'], missed: 'A replayed session token keeps {actor} in {victim}’s account from abroad.', contained: 'Token revocation and a conditional-access block locked {actor} out of the cloud.' },
      { stage: 'persistence', templates: ['endpoint-scheduled-task'], missed: 'With the mailbox as a springboard, {actor} planted a scheduled task on {host}.', contained: 'The task was removed and {host} rebuilt.' },
      { stage: 'discovery', templates: ['network-internal-portscan'], missed: '{actor} surveyed the network from {host} looking for data stores.', contained: 'IR cut {actor} off mid-reconnaissance.' },
      { stage: 'objective', templates: ['network-dns-tunneling'], missed: '{actor} smuggled data out over DNS from {host}. The data is gone.', contained: 'The tunnel was blocked at the resolver and {host} isolated before much left.' },
    ],
  },
];

export function actorById(id: string): Actor | undefined {
  return ACTORS.find((a) => a.id === id);
}

// Words and patterns real vendors use in actor names. None may appear in ours.
export const VENDOR_NAMING = /\b(apt|ta|unc|fin|temp|dev|storm|typhoon|blizzard|sleet|sandstorm|tempest|hail|rain|flood|tsunami|cyclone|dust|bear|panda|kitten|chollima|spider|jackal|tiger|buffalo|leopard|wolf|werewolf|marlin|heron|gold|iron|bronze|nickel|cobalt|tin|linen|paper|lazarus|sandworm|turla|cozy|fancy)\b|\d/i;

// Some templates need a victim with specific properties to stay coherent.
export function compatible(templateId: string, p: Person, os: string): boolean {
  if (templateId === 'identity-mfa-fatigue') return p.mfaMethod === 'Push notification';
  if (templateId.startsWith('identity-')) return true;
  return os.startsWith('Windows');
}
