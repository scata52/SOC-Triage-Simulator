// Mail gateway noise. Decoys: partner invoices with PDF attachments (what an
// invoice-themed attachment campaign hides among), bulk marketing that passes
// SPF/DKIM/DMARC aligned to the real brand, spam that fails them, and phishing
// the gateway already blocked.

import { attackerDomain, BULK_SENDERS } from '../../synth/domains.ts';
import type { Department, Person } from '../../world/world.ts';
import { HOUR } from '../time.ts';
import { within } from './presence.ts';
import type { NoiseCtx } from './context.ts';

const INTERNAL_SUBJECTS: Record<string, string[]> = {
  default: ['Quick question', 'Re: Meeting notes', 'Agenda for Thursday', 'Re: Status update', 'FYI', 'Lunch?', 'Re: Re: Draft for review'],
  Finance: ['Month-end close checklist', 'Re: Vendor payment run', 'Updated cash forecast', 'Expense approvals pending'],
  Sales: ['Pipeline review', 'Re: Client renewal', 'Territory update', 'Deal desk request'],
  Engineering: ['Release 4.2 go/no-go', 'Re: Incident review', 'On-call handover', 'Code freeze reminder'],
  HR: ['New starter onboarding', 'Re: Benefits enrolment', 'Interview panel'],
  IT: ['Maintenance window tonight', 'Re: Laptop refresh', 'Patch compliance report'],
  Operations: ['Shipment delayed', 'Re: Supplier onboarding', 'Warehouse schedule'],
};

const PARTNER_TARGETS: Record<string, Department[]> = {
  Supplier: ['Finance', 'Operations'],
  Customer: ['Sales', 'Executive'],
  'External counsel': ['Legal', 'Executive'],
  'Logistics partner': ['Operations', 'Finance'],
};

function msgId(n: NoiseCtx): string {
  return `${n.rng.hex(8)}-${n.rng.hex(4)}-${n.rng.hex(4)}-${n.rng.hex(4)}-${n.rng.hex(12)}`;
}

export function emailNoise(n: NoiseCtx): void {
  const { b, rng } = n;
  const w = b.world;
  const byDept = new Map<string, Person[]>();
  for (const p of w.people) byDept.set(p.department, [...(byDept.get(p.department) ?? []), p]);
  const hours = (b.windowEnd - b.windowStart) / HOUR;

  // Intra-org mail.
  for (const s of n.sessions) {
    const sends = rng.int(1, 4);
    for (let i = 0; i < sends; i++) {
      const pool = rng.bool(0.7) ? byDept.get(s.person.department) ?? w.people : w.people;
      const recipients = rng.sample(pool.filter((p) => p !== s.person), rng.int(1, 3));
      const id = msgId(n);
      const t = within(rng, s);
      const subject = rng.pick(INTERNAL_SUBJECTS[s.person.department] ?? INTERNAL_SUBJECTS.default);
      for (const r of recipients) {
        b.email({ TimeGenerated: t, NetworkMessageId: id, SenderFromAddress: s.person.upn, SenderDisplayName: s.person.display, SenderMailFromDomain: w.org.domain, RecipientEmailAddress: r.upn, Subject: subject, EmailDirection: 'Intra-org', DeliveryAction: 'Delivered', DeliveryLocation: 'Inbox', SPF: 'pass', DKIM: 'pass', DMARC: 'pass', BulkComplaintLevel: 0, Urls: '', AttachmentNames: rng.bool(0.15) ? `${rng.pick(['notes', 'draft', 'figures'])}.docx` : '', ThreatTypes: '' });
      }
    }
  }

  // Partners and suppliers, including invoice PDFs.
  const partnerMails = Math.round(hours * rng.float(0.6, 1.1));
  for (let i = 0; i < partnerMails; i++) {
    const partner = rng.pick(w.partners);
    const from = rng.pick(partner.contacts);
    const depts = PARTNER_TARGETS[partner.relationship] ?? ['Operations'];
    const to = rng.pick(depts.flatMap((d) => byDept.get(d) ?? []));
    if (!to) continue;
    const invoice = partner.relationship === 'Supplier' || partner.relationship === 'Logistics partner' ? rng.bool(0.5) : false;
    const n2 = rng.int(1000, 9999);
    const subject = invoice ? `Invoice INV-${n2} — ${partner.org.name}` : rng.pick([`Re: Order confirmation PO-${n2}`, 'Updated contract draft', 'Shipment ETA update', 'Meeting follow-up', 'Quarterly business review']);
    b.email({ TimeGenerated: rng.int(b.windowStart, b.windowEnd), NetworkMessageId: msgId(n), SenderFromAddress: from, SenderDisplayName: from.split('@')[0].replace('.', ' ').replace(/\b\w/g, (c) => c.toUpperCase()), SenderMailFromDomain: partner.org.domain, SenderIPv4: partner.mailIp, RecipientEmailAddress: to.upn, Subject: subject, EmailDirection: 'Inbound', DeliveryAction: 'Delivered', DeliveryLocation: 'Inbox', SPF: 'pass', DKIM: 'pass', DMARC: 'pass', BulkComplaintLevel: 0, Urls: rng.bool(0.3) ? `https://${partner.org.domain}/portal` : '', AttachmentNames: invoice ? `INV-${n2}.pdf` : rng.bool(0.3) ? 'contract_v3.docx' : '', AttachmentSHA256: invoice ? rng.hex(64) : '', ThreatTypes: '' });
  }

  // Newsletters: authenticated and aligned to the real brand.
  const bulk = Math.round(hours * rng.float(0.9, 1.6));
  for (let i = 0; i < bulk; i++) {
    const s = rng.pick(BULK_SENDERS);
    const to = rng.pick(w.people);
    const bcl = rng.int(4, 8);
    b.email({ TimeGenerated: rng.int(b.windowStart, b.windowEnd), NetworkMessageId: msgId(n), SenderFromAddress: s.from, SenderDisplayName: s.brand, SenderFromDomain: s.fromDomain, SenderMailFromDomain: s.esp, SenderIPv4: w.bulkSenderIps[s.from], RecipientEmailAddress: to.upn, Subject: rng.pick(s.subjects), EmailDirection: 'Inbound', DeliveryAction: bcl >= 7 ? 'Junked' : 'Delivered', DeliveryLocation: bcl >= 7 ? 'Junk folder' : 'Inbox', SPF: 'pass', DKIM: 'pass', DMARC: 'pass', BulkComplaintLevel: bcl, Urls: `https://${s.fromDomain}/`, AttachmentNames: '', ThreatTypes: '' });
  }

  // Spam: fails authentication, junked or blocked.
  const spam = Math.round(hours * rng.float(0.3, 0.7));
  for (let i = 0; i < spam; i++) {
    const d = attackerDomain(rng, 'dga', w.org.short);
    const to = rng.pick(w.people);
    const blocked = rng.bool(0.4);
    b.setDomainIntel(d, { ageDays: rng.int(20, 400), category: 'Spam', reputation: rng.bool(0.5) ? 'Suspicious' : 'Unknown' });
    b.email({ TimeGenerated: rng.int(b.windowStart, b.windowEnd), NetworkMessageId: msgId(n), SenderFromAddress: `${rng.pick(['promo', 'offers', 'win', 'deals'])}@${d}`, SenderDisplayName: rng.pick(['Exclusive Offer', 'Prize Team', 'Crypto Desk', 'Wellness Deals']), SenderMailFromDomain: d, SenderIPv4: rng.pick(w.internet.hosting), RecipientEmailAddress: to.upn, Subject: rng.pick(['You have won!', 'Limited time: 80% off', 'Your account bonus is waiting', 'Re: your inquiry']), EmailDirection: 'Inbound', DeliveryAction: blocked ? 'Blocked' : 'Junked', DeliveryLocation: blocked ? 'Quarantine' : 'Junk folder', SPF: rng.pick(['fail', 'softfail', 'none']), DKIM: 'none', DMARC: 'fail', BulkComplaintLevel: 9, Urls: `http://${d}/offer`, AttachmentNames: '', ThreatTypes: 'Spam' });
  }

  // Phishing the gateway caught at delivery time.
  const phish = Math.max(1, Math.round(hours * rng.float(0.1, 0.2)));
  for (let i = 0; i < phish; i++) {
    const d = attackerDomain(rng, rng.pick(['lure', 'lookalike'] as const), w.org.short);
    const to = rng.pick(w.people);
    b.setDomainIntel(d, { ageDays: rng.int(1, 25), category: 'Newly Registered Domain', reputation: 'Suspicious' });
    b.email({ TimeGenerated: rng.int(b.windowStart, b.windowEnd), NetworkMessageId: msgId(n), SenderFromAddress: `${rng.pick(['no-reply', 'security', 'itsupport', 'docs'])}@${d}`, SenderDisplayName: rng.pick(['Microsoft 365', 'IT Service Desk', 'Document Share', 'Payroll Team']), SenderMailFromDomain: d, SenderIPv4: rng.pick(w.internet.hosting), RecipientEmailAddress: to.upn, Subject: rng.pick(['Action required: verify your mailbox', 'You have 3 pending documents', 'Payroll adjustment notice', 'Password expiry notice']), EmailDirection: 'Inbound', DeliveryAction: 'Blocked', DeliveryLocation: 'Quarantine', SPF: 'pass', DKIM: 'pass', DMARC: 'pass', BulkComplaintLevel: 1, Urls: `https://${d}/login`, AttachmentNames: '', ThreatTypes: 'Phish' });
  }

  // Outbound to partners.
  for (const s of n.sessions) {
    if (!['Sales', 'Finance', 'Operations', 'Legal'].includes(s.person.department) || !rng.bool(0.5)) continue;
    const partner = rng.pick(w.partners);
    b.email({ TimeGenerated: within(rng, s), NetworkMessageId: msgId(n), SenderFromAddress: s.person.upn, SenderDisplayName: s.person.display, SenderMailFromDomain: w.org.domain, RecipientEmailAddress: rng.pick(partner.contacts), Subject: rng.pick(['Re: Proposal', 'Signed agreement attached', 'Payment confirmation', 'Follow-up from our call']), EmailDirection: 'Outbound', DeliveryAction: 'Delivered', DeliveryLocation: 'Inbox', SPF: 'pass', DKIM: 'pass', DMARC: 'pass', BulkComplaintLevel: 0, Urls: '', AttachmentNames: rng.bool(0.3) ? 'agreement_signed.pdf' : '', ThreatTypes: '' });
  }
}
