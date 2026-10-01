// Class and vector coherence (a finding's vector must fit what it is). The
// project's definition of a contradiction between a vulnerability class, its
// component and its CVSS vector. The catalogue generator only emits entries that
// pass it, and scenario templates re-export it (templates/common.ts).

import { VULN_CLASS_LABELS, type VulnClass } from './classes.ts';

// The fields of a catalogue entry that coherence needs (structural, so catalogue.ts need not be imported).
interface CoherenceSubject {
  vector: string;
  vulnClass: VulnClass;
  component: string;
  title: string;
}

const metricsOf = (vector: string): Record<string, string> => Object.fromEntries(vector.split('/').slice(1).map((p) => p.split(':') as [string, string]));

// Component rules: a network-facing component cannot be attacked from the local
// machine only, and a login or pre-auth component needs no privileges. A local
// component (installer profile, permissions template, scripting console, or a handler that opens a local
// document or project file) may be AV:L.
const NETWORK_COMPONENT = /database listener|endpoint|login form|query parameter|callback|management interface|cross-origin|status page|file-upload|file-download|download handler|request parser|session handler|password reset|token check|admin console|directory listing|debug|update service|protocol negotiator|template engine|report filter|log viewer|error handler|image renderer|compression module/i;
// A scripting console, a document preview handler or a project file importer (rce) may be reached locally or over the network; an installer profile or a permissions
// template is only ever a local matter.
const LOCAL_OK_COMPONENT = /installer profile|permissions template|scripting console|document preview handler|project file importer/i;
const LOCAL_ONLY_COMPONENT = /installer profile|permissions template/i;
const PRE_AUTH_COMPONENT = /login form|sso callback|password reset|default credentials/i;
// Exposure components need no login and no user action. A physical vector fits only a physical component
// (never a web or network-facing one), and a physical component is never reached from the network.
const EXPOSURE_COMPONENT = /directory listing|debug endpoint|metrics endpoint|backup file exposure/i;
// rce components where a user loads or opens attacker content, so UI:R is plausible. Every other rce component
// (template engine, file-upload handler, update service, deserialization endpoint, request parser...) is server-side.
const USER_OPENS_COMPONENT = /plugin loader|scripting console|document preview handler|project file importer/i;
const PHYSICAL_COMPONENT = /firmware|boot loader|console port/i;

// Why a vector cannot belong to a flaw of this class and description, or null
// when it can. `text` is the component or the whole title.
export function vectorProblem(vector: string, vulnClass: VulnClass, text: string): string | null {
  const m = metricsOf(vector);
  const label = VULN_CLASS_LABELS[vulnClass];
  if (vulnClass === 'rce' && !((m.AV === 'N' || m.AV === 'A' || (m.AV === 'L' && LOCAL_OK_COMPONENT.test(text))) && m.I === 'H')) return `${label} needs a network-reachable vector with high integrity impact`;
  if (vulnClass === 'sqli' && m.AV !== 'N') return `${label} needs a network vector`;
  if (vulnClass === 'auth-bypass' && m.PR !== 'N') return `${label} needs no privileges required`;
  if ((vulnClass === 'sqli' || vulnClass === 'auth-bypass') && m.C === 'N' && m.I === 'N') return `${label} needs a confidentiality or integrity impact`;
  if (/license service|API token check|admin console|SSO callback/i.test(text) && m.UI !== 'N') return `"${text}" needs no user interaction`;
  if (/default credentials|admin console/i.test(text) && m.PR !== 'N') return `"${text}" needs no privileges required`;
  if (vulnClass === 'info-leak' && !((m.C === 'L' || m.C === 'H') && m.I === 'N')) return `${label} needs a confidentiality impact and no integrity impact`;
  if (vulnClass === 'dos' && !((m.A === 'L' || m.A === 'H') && m.C === 'N' && m.I === 'N')) return `${label} needs an availability impact only`;
  // A TLS weakness exposes traffic confidentiality (and at most limited integrity), never availability.
  if (/tls/i.test(text) && !(m.AV === 'N' && m.PR === 'N' && m.UI === 'N' && m.A === 'N' && m.C !== 'N' && m.I !== 'H')) return 'a TLS flaw needs a network vector, no privileges or user interaction, a confidentiality impact, no availability impact and no high integrity impact';
  // UI:R means another user takes part. Server-side request handling needs none; only a component where a user
  // loads or opens attacker content (a plugin loader, a scripting console, a document preview handler, a project file importer) may need it.
  if (vulnClass === 'rce' && m.UI === 'R' && !USER_OPENS_COMPONENT.test(text)) return `"${text}" is server-side and needs no user interaction`;
  // A scope change needs a crossed security authority; an error handler or a log viewer stays inside its own.
  if (vulnClass === 'info-leak' && m.S === 'C' && /error handler|log viewer/i.test(text)) return `"${text}" stays inside one security authority, so the scope cannot change`;
  if (/protocol/i.test(text) && !(m.AV === 'N' && m.PR === 'N')) return 'a protocol flaw needs a network vector and no privileges required';
  if (m.AV === 'P' && !PHYSICAL_COMPONENT.test(text)) return `"${text}" is not a physical component and cannot need physical access`;
  if (PHYSICAL_COMPONENT.test(text) && m.AV !== 'P' && m.AV !== 'L') return `"${text}" is a physical or local component and cannot be reached over the network`;
  if (NETWORK_COMPONENT.test(text) && !LOCAL_OK_COMPONENT.test(text) && m.AV !== 'N' && m.AV !== 'A') return `"${text}" is a network-facing component and needs a network or adjacent vector`;
  if (LOCAL_ONLY_COMPONENT.test(text) && m.AV !== 'L') return `"${text}" is a local component and needs a local vector`;
  if (/cross-origin policy/i.test(text) && !(m.UI === 'R' && m.A === 'N')) return `"${text}" needs user interaction and no availability impact`;
  if (/default credentials/i.test(text) && (m.UI !== 'N' || (m.C === 'N' && m.I === 'N'))) return `"${text}" needs no user interaction and a confidentiality or integrity impact`;
  if (EXPOSURE_COMPONENT.test(text) && m.C === 'N') return `"${text}" needs a confidentiality impact`;
  if (EXPOSURE_COMPONENT.test(text) && !(m.UI === 'N' && m.PR === 'N')) return `"${text}" needs no user interaction and no privileges required`;
  // A file share or remote shell misconfiguration needs no other user to act and changes no scope; a remote shell is network-bound.
  if (/file share permissions|remote shell settings|database listener settings/i.test(text) && !(m.UI === 'N' && m.S === 'U')) return `"${text}" needs no user interaction and cannot change scope`;
  if (/remote shell settings/i.test(text) && m.AV !== 'N') return `"${text}" is network-bound and needs a network vector`;
  // A file share is reached over SMB or NFS and exposes or alters data, so it is never availability-only.
  if (/file share permissions/i.test(text) && m.AV !== 'N') return `"${text}" is reached over SMB or NFS and needs a network vector`;
  if (/file share permissions/i.test(text) && m.C === 'N' && m.I === 'N') return `"${text}" needs a confidentiality or integrity impact`;
  // A shell misconfiguration gives command execution as the account: never a single partial impact.
  if (/remote shell settings/i.test(text) && [m.C, m.I, m.A].filter((x) => x !== 'N').length < 2) return `"${text}" gives command execution and needs at least two of confidentiality, integrity and availability impacts`;
  if (PRE_AUTH_COMPONENT.test(text) && m.PR !== 'N') return `"${text}" is reachable before login and needs no privileges required`;
  return null;
}

export const vectorFits = (vector: string, vulnClass: VulnClass, text: string): boolean => vectorProblem(vector, vulnClass, text) === null;

// A catalogue entry whose class, title and vector agree.
export const isCoherent = (e: CoherenceSubject): boolean => vectorFits(e.vector, e.vulnClass, `${e.component} ${e.title}`);
