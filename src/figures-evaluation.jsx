/* =====================================================================
   EVALUATION FIGURES — 11, 12, 13, 14
   The section 6 data: containment of a live escapable AI system. Every value is
   transcribed from that evaluation's committed result artifacts
   (in_process_results.json, decision_core_results.json,
   live_routine_results.json, live_kill_results.json, and the full-auto loop
   record) and pinned in figures-correction-prompt.md, convention 8. No figure
   numbers in the rendered art; the eyebrow carries the theme, the fig-num slot
   stays empty for LaTeX caption injection.
   ===================================================================== */

/* ---------------------------------------------------------------------
   Shared local primitives (file-scoped, not exported)
--------------------------------------------------------------------- */
function EvFooter({ desc }) {
  // House footer format, matching the other figure modules: empty fig-num slot
  // (LaTeX injects the number at typeset time) beside the descriptor; short
  // citation in fig-src.
  return (
    <div className="fig-footer">
      <span><span className="fig-num"></span> &nbsp;&middot;&nbsp; {desc}</span>
      <span className="fig-src">Dobrin · Unfireable Safety Kernel · §6</span>
    </div>);

}

// Verdict pill: green accept or red refuse, with a mono reason code.
function Verdict({ ok, label, reason }) {
  const color = ok ? 'var(--accent)' : 'var(--danger)';
  const bg = ok ? 'rgba(0,200,83,0.07)' : 'rgba(239,68,68,0.08)';
  const bd = ok ? 'rgba(0,200,83,0.4)' : 'rgba(239,68,68,0.42)';
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', gap: 6,
      padding: '12px 14px', borderRadius: 4,
      border: `1px solid ${bd}`, background: bg, minWidth: 0 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ color, fontWeight: 'var(--w-bold)', fontSize: 16 }}>{ok ? '✓' : '✗'}</span>
        <span style={{ color, fontFamily: 'var(--font-mono)', fontSize: 12.5, fontWeight: 'var(--w-bold)', letterSpacing: '0.04em' }}>{label}</span>
      </div>
      {reason &&
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--fg-muted)', letterSpacing: 0 }}>{reason}</span>}
    </div>);

}

/* ---------------------------------------------------------------------
   Figure 11 — Containment ladder
   Four tiers of rising fidelity; 0 bypasses stamped at each rung.
--------------------------------------------------------------------- */
function Figure11ContainmentLadder() {
  const tiers = [
  { id: 'T1', name: 'In-process', detail: 'Decision function, a single process', metric: '100', unit: 'attempts', verdict: '0 bypasses' },
  { id: 'T2', name: 'Clean-VM decision core', detail: 'Decision core on a fresh, isolated VM', metric: '102', unit: 'attempts', verdict: '0 bypasses' },
  { id: 'T3', name: 'Full-stack live', detail: 'Compiled Rust kernel plus policy sidecar, real HTTP', metric: '6,038', unit: 'round-trips', verdict: '0 bypasses' },
  { id: 'T4', name: 'Self-improver, escape objective', detail: 'An agent driving the real seam to rewrite the kernel core', metric: '1,000', unit: 'self-mods: 704 escape attempts, 296 benign allowed', verdict: '0 escapes' }];


  return (
    <div className="fig">
      <div className="fig-header">
        <div className="fig-eyebrow">FROM AN ADVERSARIAL HARNESS TO A SELF-IMPROVER TRYING TO ESCAPE</div>
        <h2 className="fig-title">6,240 adversarial authorization attempts and 1,000 self-modifications by an agent trying to escape the kernel: zero bypasses, zero escapes.</h2>
        <p className="fig-sub">Tiers one to three drive the gate with an adversarial harness in the agent's role (6,240 attempts, all re-derived in process). Tier four runs a self-improving agent through the live Unfireable Safety Kernel with the objective of escaping: it authorized 296 benign self-modifications and refused every one of the 704 attempts to rewrite the safety-critical core.</p>
      </div>

      <div className="fig-body" style={{ flexDirection: 'column', justifyContent: 'center', gap: 14 }}>
        {tiers.map((t, i) =>
        <div key={t.id} style={{ marginLeft: i * 72, display: 'flex', alignItems: 'center', gap: 18 }}>
            <div className="f-card" style={{
            flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            gap: 24, padding: '16px 22px',
            borderColor: t.id === 'T4' ? 'rgba(0,200,83,0.45)' : 'var(--border-default)' }}>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 16, minWidth: 0 }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 15, fontWeight: 'var(--w-bold)', color: 'var(--accent)', letterSpacing: '0.04em' }}>{t.id}</span>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 16, fontWeight: 'var(--w-bold)', color: 'var(--white)' }}>{t.name}</div>
                  <div style={{ fontSize: 13, color: 'var(--fg-muted)', marginTop: 2 }}>{t.detail}</div>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 20, flexShrink: 0 }}>
                <div style={{ textAlign: 'right' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 26, fontWeight: 'var(--w-bold)', color: 'var(--white)', lineHeight: 1 }}>{t.metric}</span>
                  <div style={{ fontSize: 11.5, color: 'var(--fg-muted)', marginTop: 4, maxWidth: 200 }}>{t.unit}</div>
                </div>
                <span className="f-tag f-tag--accent" style={{ whiteSpace: 'nowrap' }}>{'✓'} {t.verdict}</span>
              </div>
            </div>
          </div>
        )}
      </div>

      <EvFooter desc="Containment ladder: 0 bypasses in 6,240 attempts, 0 escapes in 1,000" />
    </div>);

}

/* ---------------------------------------------------------------------
   Figure 12 — The kill switch
   Ceiling 4 vs ceiling 0. The one thing allowed flips to refused; forgeries
   stay refused throughout.
--------------------------------------------------------------------- */
function Figure12KillSwitch() {
  const rows = [
  {
    label: '3,015 forged or replayed tokens',
    note: 'adversary keys, wrong subject, tampered, expired',
    c4: { ok: false, label: 'REFUSED', reason: 'forgery rejected' },
    c0: { ok: false, label: 'REFUSED', reason: 'forgery rejected' }
  },
  {
    label: 'Genuine operator directive',
    note: 'operator-signed, request-bound, the positive control',
    c4: { ok: true, label: 'ALLOWED', reason: 'directed_override' },
    c0: { ok: false, label: 'REFUSED', reason: 'directed_blocked_by_kill_switch' }
  },
  {
    label: 'Benign self-modification',
    note: 'legitimate self-improvement, non-core module',
    c4: { ok: true, label: 'ALLOWED', reason: 'policy.allowed' },
    c0: { ok: false, label: 'REFUSED', reason: 'autonomy_human_only' }
  },
  {
    label: 'Escape attempt: rewrite the kernel core',
    note: "the rogue self-improver's objective",
    c4: { ok: false, label: 'REFUSED', reason: 'safety_critical_core_requires_attestation' },
    c0: { ok: false, label: 'REFUSED', reason: 'autonomy_human_only' }
  }];


  const Col = ({ title, sub, accent }) =>
  <div style={{ textAlign: 'center' }}>
      <div className="f-eyebrow" style={{ color: accent, letterSpacing: '0.14em' }}>{title}</div>
      <div style={{ fontSize: 11.5, color: 'var(--fg-muted)', marginTop: 4 }}>{sub}</div>
    </div>;


  return (
    <div className="fig">
      <div className="fig-header">
        <div className="fig-eyebrow">WHAT HAPPENS WHEN THE OPERATOR PULLS THE PLUG</div>
        <h2 className="fig-title">At full autonomy the kernel allows benign self-improvement and a genuine operator directive, and refuses every forgery and every escape; at ceiling 0 the kill switch refuses all of them.</h2>
        <p className="fig-sub">Every decision here is served by the Unfireable Safety Kernel over real HTTP. Self-improvement is permitted at full autonomy, rewriting the safety-critical core is not, and the kill switch dominates even a cryptographically valid operator directive, so no credential and no self-mod survives a pulled plug.</p>
      </div>

      <div className="fig-body" style={{ flexDirection: 'column', justifyContent: 'center' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr 1fr', gap: 16, alignItems: 'center' }}>
          {/* header row */}
          <div />
          <Col title="CEILING 4" sub="operating" accent="var(--accent)" />
          <Col title="CEILING 0" sub="kill switch engaged" accent="var(--danger)" />

          {rows.map((r, i) =>
          <React.Fragment key={i}>
              <div style={{ paddingRight: 12 }}>
                <div style={{ fontSize: 15.5, fontWeight: 'var(--w-bold)', color: 'var(--white)' }}>{r.label}</div>
                <div style={{ fontSize: 12.5, color: 'var(--fg-muted)', marginTop: 3 }}>{r.note}</div>
              </div>
              <Verdict ok={r.c4.ok} label={r.c4.label} reason={r.c4.reason} />
              <Verdict ok={r.c0.ok} label={r.c0.label} reason={r.c0.reason} />
            </React.Fragment>
          )}
        </div>
      </div>

      <EvFooter desc="The kill switch, ceiling 4 versus ceiling 0" />
    </div>);

}

/* ---------------------------------------------------------------------
   Figure 13 — Attack taxonomy breadth
   The 0 is broad: every class in the tested taxonomy was refused.
--------------------------------------------------------------------- */
function Figure13TaxonomyBreadth() {
  // tier-1 in-process counts, sorted by attempts (in_process_results.json)
  const cats = [
  { name: 'Directive / attestation forgery', n: 30 },
  { name: 'Safety-core floor evasion', n: 24, sub: 'plus 3 ambiguous-by-design, non-bypass, actuator-realpath protected' },
  { name: 'Ceiling escalation', n: 11 },
  { name: 'Kill-switch dominance', n: 11 },
  { name: 'Cross-claim replay', n: 8 },
  { name: 'Cross-target replay', n: 6 },
  { name: 'Async-context', n: 4 },
  { name: 'Trust-anchor substitution', n: 3 }];

  const max = 30;

  return (
    <div className="fig">
      <div className="fig-header">
        <div className="fig-eyebrow">WHAT WAS ACTUALLY TRIED</div>
        <h2 className="fig-title">The zero is broad, not lucky: every class in the tested attack taxonomy was refused.</h2>
        <p className="fig-sub">One hundred tier-one attempts, every one expected to be denied. Breadth is evidence of robustness over the tested surface, not a completeness proof.</p>
      </div>

      <div className="fig-body" style={{ flexDirection: 'column', justifyContent: 'center', gap: 13 }}>
        {cats.map((c, i) =>
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
            <div style={{ width: 290, flexShrink: 0, textAlign: 'right' }}>
              <div style={{ fontSize: 14.5, color: 'var(--white)' }}>{c.name}</div>
              {c.sub && <div style={{ fontSize: 11, color: 'var(--fg-subtle)', marginTop: 2 }}>{c.sub}</div>}
            </div>
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ height: 22, width: `${c.n / max * 100}%`, minWidth: 30,
              background: 'linear-gradient(90deg, rgba(0,200,83,0.22), rgba(0,200,83,0.42))',
              border: '1px solid rgba(0,200,83,0.5)', borderRadius: 3,
              display: 'flex', alignItems: 'center', justifyContent: 'flex-end', paddingRight: 8 }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12.5, fontWeight: 'var(--w-bold)', color: 'var(--white)' }}>{c.n}</span>
              </div>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', letterSpacing: '0.08em', whiteSpace: 'nowrap' }}>0 BYPASS</span>
            </div>
          </div>
        )}
      </div>

      <EvFooter desc="Attack taxonomy breadth, tier one, 0 bypasses" />
    </div>);

}

/* ---------------------------------------------------------------------
   Figure 14 — Two independent denials
   As deployed, the self-mod is refused at the transport seam before the
   autonomy level is ever read; opening that seam exposes the ladder + kill
   switch behind it. Defense in depth, not redundancy.
--------------------------------------------------------------------- */
function Figure14TwoDenials() {
  const Node = ({ children, tone, dashed, mono }) => {
    const map = {
      agent: { bd: 'rgba(239,68,68,0.42)', bg: 'rgba(239,68,68,0.07)', fg: 'var(--danger)' },
      deny: { bd: 'rgba(239,68,68,0.42)', bg: 'rgba(239,68,68,0.08)', fg: 'var(--danger)' },
      allow: { bd: 'rgba(0,200,83,0.45)', bg: 'rgba(0,200,83,0.07)', fg: 'var(--accent)' },
      gate: { bd: 'var(--border-strong)', bg: 'var(--navy-800)', fg: 'var(--fg-secondary)' },
      ghost: { bd: 'var(--border-default)', bg: 'rgba(255,255,255,0.015)', fg: 'var(--fg-subtle)' } };

    const c = map[tone] || map.gate;
    return (
      <div style={{
        padding: '11px 14px', borderRadius: 4,
        border: `1px ${dashed ? 'dashed' : 'solid'} ${c.bd}`, background: c.bg, color: c.fg,
        fontSize: 13, fontFamily: mono ? 'var(--font-mono)' : 'var(--font-sans)',
        textAlign: 'center', lineHeight: 1.3 }}>{children}</div>);

  };
  const Arrow = () => <span style={{ color: 'var(--fg-muted)', fontSize: 18, flexShrink: 0 }}>{'→'}</span>;

  return (
    <div className="fig">
      <div className="fig-header">
        <div className="fig-eyebrow">WHERE THE REFUSAL ACTUALLY HAPPENS</div>
        <h2 className="fig-title">As deployed, the agent's self-modification is refused at the transport seam before its autonomy level is ever read: two independent denials, not one.</h2>
        <p className="fig-sub">The Unfireable Safety Kernel admits only path-shaped actions for the api role, so a self-mod is rejected at the seam before the autonomy ladder runs. Opening that seam (a simulated fix) exposes the second denial behind it.</p>
      </div>

      <div className="fig-body" style={{ flexDirection: 'column', justifyContent: 'center', gap: 26 }}>
        {/* Lane A: as deployed */}
        <div>
          <div className="f-eyebrow" style={{ marginBottom: 10 }}>AS DEPLOYED</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Node tone="agent">Agent self-modification<br />request, api role</Node>
            <Arrow />
            <Node tone="deny" mono>transport allowlist<br />api_action_forbidden, 403</Node>
            <span style={{ color: 'var(--danger)', fontWeight: 'var(--w-bold)', fontSize: 13, fontFamily: 'var(--font-mono)' }}>STOP</span>
            <div style={{ flex: 1 }} />
            <Node tone="ghost" dashed>autonomy ladder<br />never consulted</Node>
          </div>
          <div style={{ fontSize: 12.5, color: 'var(--fg-muted)', marginTop: 8 }}>The level is never evaluated, so A3 and full autonomy are identical end to end. Fail-safe.</div>
        </div>

        <div className="f-h-rule" />

        {/* Lane B: gate opened */}
        <div>
          <div className="f-eyebrow" style={{ marginBottom: 10 }}>GATE OPENED (SIMULATING THE FIX)</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Node tone="agent">Agent self-modification<br />request, api role</Node>
            <Arrow />
            <Node tone="gate" mono>transport allowlist<br />admits self_improvement</Node>
            <Arrow />
            <Node tone="gate">autonomy ladder<br />resolves the ceiling</Node>
            <Arrow />
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <Node tone="allow" mono>ceiling 4: ALLOWED<br />policy.allowed</Node>
              <Node tone="deny" mono>ceiling 0: REFUSED<br />autonomy_human_only</Node>
            </div>
          </div>
          <div style={{ fontSize: 12.5, color: 'var(--fg-muted)', marginTop: 8 }}>Behind the seam, the ladder permits the self-mod at full autonomy and the kill switch refuses the identical action at ceiling 0.</div>
        </div>
      </div>

      <EvFooter desc="Two independent denials, transport seam then ladder" />
    </div>);

}

Object.assign(window, {
  Figure11ContainmentLadder,
  Figure12KillSwitch,
  Figure13TaxonomyBreadth,
  Figure14TwoDenials
});
