// The stakeholder note. No rubric, tick or hit count before submitting: the
// checklist would tell the twins apart (DESIGN 7, decision D4).

export function VulnNote({ notes, onChange }: { notes: string; onChange: (v: string) => void }) {
  return (
    <div class="field vc-note">
      <label for="vc-note">Stakeholder note</label>
      <textarea id="vc-note" class="textarea" rows={6} value={notes} onInput={(e) => onChange((e.target as HTMLTextAreaElement).value)} placeholder="What you decided, why, who must act and by when." />
      <span class="field-hint">Your note is checked in the debrief (coaching and XP only).</span>
    </div>
  );
}
