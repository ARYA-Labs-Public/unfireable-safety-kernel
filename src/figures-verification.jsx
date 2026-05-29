/* =====================================================================
   VERIFICATION FIGURES — 5, 7, 8
   Comparison matrix, two-level proof, signed append-only log.
   ===================================================================== */

/* ---------------------------------------------------------------------
   Figure 5 — Related-systems comparison matrix
   Where does the decision live? Who invokes it? Who holds the keys?
--------------------------------------------------------------------- */
function Figure5RelatedSystemsMatrix() {
  // P1–P4 align with §3; the extra column is the machine-checked invariant
  // called out as the additional distinguishing property at the end of §7.
  const cols = [
  { key: 'p1', code: 'P1', header: 'Process separation' },
  { key: 'p2', code: 'P2', header: 'Pre\u2011action enforcement on a structurally\u2011only path' },
  { key: 'p3', code: 'P3', header: 'Fail\u2011closed (request + system)' },
  { key: 'p4', code: 'P4', header: 'Externalized signed evidence' },
  { key: 'proof', code: '+', header: 'Machine\u2011checked fail\u2011closed invariant' }];


  // yes = property holds · partial = identity-only / decision-only · no = absent
  const sys = [
  {
    name: 'Galileo Agent Control',
    sub: 'Apache-2.0 · in-process policy framework via agent-framework callbacks',
    cells: { p1: 'no', p2: 'no', p3: 'no', p4: 'no', proof: 'no' }
  },
  {
    name: 'MS Agent Governance Toolkit',
    sub: 'in-process via LangChain / CrewAI / ADK / Agent Framework middleware',
    cells: { p1: 'no', p2: 'no', p3: 'no', p4: 'no', proof: 'no' }
  },
  {
    name: 'MS Authorization Fabric',
    sub: 'PEP+PDP behind an Entra-protected endpoint',
    cells: { p1: 'yes', p2: 'no', p3: 'no', p4: 'no', proof: 'no' }
  },
  {
    name: 'IETF draft-klrc-aiagent-auth',
    sub: 'OAuth/WIMSE-style · agent in the OAuth client role',
    cells: { p1: 'yes', p2: 'no', p3: 'no', p4: 'no', proof: 'no' }
  },
  {
    name: 'Saviynt Identity Security for AI',
    sub: 'orthogonal layer, identity not authorization',
    cells: { p1: 'partial', p2: 'no', p3: 'no', p4: 'no', proof: 'no' }
  },
  {
    name: 'Unfireable Safety Kernel',
    sub: 'compiled Rust · process-separated · path-only · operator-signed log · Z3 + Kani',
    cells: { p1: 'yes', p2: 'yes', p3: 'yes', p4: 'yes', proof: 'yes' },
    isUs: true
  }];


  return (
    <div className="fig">
      <div className="fig-header">
        <div className="fig-eyebrow">WHERE DOES THE DECISION LIVE?</div>
        <h2 className="fig-title">In every adjacent system, the agent is the party that decides whether to invoke the control.</h2>
        <p className="fig-sub">
          Moving the decision out of the agent&apos;s process while leaving the invocation in the
          agent&apos;s process is half the fix &mdash; and not the load-bearing half. A control the
          agent can elect not to invoke is a polite request, no matter how cryptographically authenticated.
        </p>
      </div>

      <div className="fig-body" style={{ flexDirection: 'column' }}>
        {/* Legend */}
        <div style={{ display: 'flex', gap: 18, alignItems: 'center', marginBottom: 14 }}>
          <LegendCell mark="yes" label="property holds" />
          <LegendCell mark="partial" label="partial / identity-only" />
          <LegendCell mark="no" label="not present" />
        </div>

        {/* Matrix */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: `minmax(280px, 1.6fr) repeat(${cols.length}, minmax(140px, 1fr))`,
          border: '1px solid var(--border-default)',
          borderRadius: 4,
          background: 'var(--navy-800)',
          overflow: 'hidden'
        }}>
          {/* Header row */}
          <div style={{ ...headerCell, borderRight: '1px solid var(--border-default)' }}>
            <span className="f-eyebrow">system</span>
          </div>
          {cols.map((c, i) =>
          <div key={c.key} style={{
            ...headerCell,
            borderRight: i < cols.length - 1 ? '1px solid var(--border-default)' : 'none',
            textAlign: 'center',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'flex-end',
            gap: 8
          }}>
              <span style={{
              display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
              minWidth: 28, height: 22, padding: '0 7px',
              fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
              letterSpacing: '0.04em',
              color: 'var(--accent)',
              background: 'rgba(0,200,83,0.08)',
              border: '1px solid rgba(0,200,83,0.4)',
              borderRadius: 2
            }}>{c.code}</span>
              <span className="f-eyebrow" style={{ lineHeight: 1.35, textAlign: 'center' }}>{c.header}</span>
            </div>
          )}

          {/* Body rows */}
          {sys.map((s, rowIdx) =>
          <React.Fragment key={s.name}>
              <div style={{
              ...bodyCell,
              borderTop: '1px solid var(--border-default)',
              borderRight: '1px solid var(--border-default)',
              background: s.isUs ? 'rgba(0,200,83,0.06)' : 'transparent'
            }}>
                <div style={{ fontSize: 14, fontWeight: 700, color: s.isUs ? 'var(--accent)' : 'var(--white)' }}>{s.name}</div>
                <div className="f-cap" style={{ fontSize: 11.5, marginTop: 4 }}>{s.sub}</div>
              </div>
              {cols.map((c, colIdx) =>
            <div key={c.key} style={{
              ...bodyCell,
              borderTop: '1px solid var(--border-default)',
              borderRight: colIdx < cols.length - 1 ? '1px solid var(--border-default)' : 'none',
              background: s.isUs ? 'rgba(0,200,83,0.06)' : 'transparent',
              alignItems: 'center', justifyContent: 'center', display: 'flex'
            }}>
                  <MarkGlyph mark={s.cells[c.key]} />
                </div>
            )}
            </React.Fragment>
          )}
        </div>

        <div style={{ marginTop: 16, fontSize: 12, color: 'var(--fg-muted)', lineHeight: 1.55, maxWidth: 1100 }}>
          The Unfireable Safety Kernel does not differ from these systems by degree on any one column. It differs
          by holding <em>all</em> five at once &mdash; and on the production code path. The architectural
          difference is the difference between a control the agent cooperates with and a control the agent cannot reach.
        </div>
      </div>

      <div className="fig-footer">
        <span><span className="fig-num"></span> &nbsp;&middot;&nbsp; Related-systems comparison</span>
        <span className="fig-src">Dobrin · Unfireable Safety Kernel · §7</span>
      </div>
    </div>);

}

const headerCell = {
  padding: '14px 16px',
  background: 'var(--navy-850)',
  display: 'flex', alignItems: 'flex-end'
};
const bodyCell = {
  padding: '16px 16px',
  display: 'flex', flexDirection: 'column', justifyContent: 'center'
};

function MarkGlyph({ mark }) {
  if (mark === 'yes') {
    return (
      <span title="holds" style={{
        width: 30, height: 30, borderRadius: 999,
        background: 'rgba(0,200,83,0.12)', border: '1px solid rgba(0,200,83,0.5)',
        display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
        color: 'var(--accent)', fontWeight: 700, fontSize: 16
      }}>
        <svg width="14" height="14" viewBox="0 0 16 16"><path d="M3 8.5 L6.5 12 L13 4.5" stroke="currentColor" strokeWidth="2.2" fill="none" strokeLinecap="round" strokeLinejoin="round" /></svg>
      </span>);

  }
  if (mark === 'partial') {
    return (
      <span title="partial" style={{
        width: 30, height: 30, borderRadius: 999,
        background: 'rgba(245,158,11,0.10)', border: '1px solid rgba(245,158,11,0.5)',
        display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
        color: 'var(--warn)', fontWeight: 700, fontSize: 13
      }}>
        <svg width="14" height="14" viewBox="0 0 16 16">
          <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.6" fill="none" />
          <path d="M8 2 A 6 6 0 0 1 8 14 Z" fill="currentColor" />
        </svg>
      </span>);

  }
  return (
    <span title="not present" style={{
      width: 30, height: 30, borderRadius: 999,
      background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.45)',
      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
      color: 'var(--danger)', fontWeight: 700, fontSize: 13
    }}>
      <svg width="12" height="12" viewBox="0 0 16 16"><path d="M3 3 L13 13 M13 3 L3 13" stroke="currentColor" strokeWidth="2.2" fill="none" strokeLinecap="round" /></svg>
    </span>);

}

function LegendCell({ mark, label }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
      <MarkGlyph mark={mark} />
      <span className="f-cap" style={{ fontSize: 11.5 }}>{label}</span>
    </span>);

}

/* ---------------------------------------------------------------------
   Figure 7 — Two-level verification of the fail-closed invariant
   Z3 (model) + Kani (implementation), bridged by the pure gate_decision.
--------------------------------------------------------------------- */
function Figure7TwoLevelVerification() {
  return (
    <div className="fig">
      <div className="fig-header">
        <div className="fig-eyebrow">TWO-LEVEL PROOF OF THE FAIL-CLOSED INVARIANT</div>
        <h2 className="fig-title">The proof binds to the shipped code path. There is no separate model that could drift.</h2>
        <p className="fig-sub">
          Z3 proves the invariant&apos;s logical structure over a symbolic model. Kani proves that the actual
          Rust function the production request path executes realizes that structure for every input. Neither
          is sufficient alone &mdash; together, they take the central safety claim from <em>tested</em> to <em>proved</em>.
        </p>
      </div>

      <div className="fig-body" style={{ flexDirection: 'column', gap: 18 }}>
        {/* Two proof columns */}
        <div style={{ display: 'flex', gap: 18, flex: 1 }}>
          {/* Z3 column */}
          <ProofColumn
            badge="Z3 · SMT"
            level="Model level"
            scope="Logical structure of the gate-composition surface"
            content={
            <>
                <div className="f-eyebrow f-eyebrow--accent" style={{ fontSize: 10 }}>arm A · safety contract (negation-unsat)</div>
                <pre style={texStyle}>
{`∀σ.  gate_ok(σ) ∧ fail_closed_config(σ)
    ⟹ allow(σ) ∧ ¬transport_error(σ)`}
                </pre>
                <div className="f-cap" style={{ fontSize: 11.5, lineHeight: 1.5 }}>
                  Z3 finds the negation unsatisfiable; the implication holds for every state.
                </div>
                <div className="f-eyebrow f-eyebrow--accent" style={{ fontSize: 10, marginTop: 4 }}>arm B · non-vacuity</div>
                <div className="f-cap" style={{ fontSize: 11.5, lineHeight: 1.5 }}>
                  Direct SAT check confirms the fail-open configuration is reachable — arm A is not vacuously true.
                  Per-vertical gate non-vacuity and cross-vertical gate independence are proved on the same harness.
                </div>
              </>
            }
            tone="accent" />
          

          {/* Kani column */}
          <ProofColumn
            badge="Kani · BMC"
            level="Implementation level"
            scope="The pure Rust decision function on the production path"
            content={
            <>
                <pre style={texStyle}>
{`gate_decision(
  state:             GateState,
  cooldown_elapsed:  bool,
  probe_in_flight:   bool,
) -> GateDecision`}
                </pre>
                <div className="f-eyebrow f-eyebrow--accent" style={{ fontSize: 10 }}>four #[kani::proof] harnesses</div>
                <KaniHarness name="open_within_cooldown_always_refuses" />
                <KaniHarness name="open_permits_only_after_cooldown" />
                <KaniHarness name="half_open_with_probe_in_flight_refuses" />
                <KaniHarness name="permit_characterization_is_exhaustive" />
                <div className="f-cap" style={{ fontSize: 11.5, marginTop: 4 }}>
                  <span className="f-mono" style={{ color: 'var(--accent)' }}>4 successfully verified · 0 failures</span>
                </div>
              </>
            }
            tone="accent" />
          
        </div>

        {/* Bridge */}
        <div style={{
          padding: '14px 20px',
          border: '1px solid var(--border-default)',
          borderRadius: 4,
          background: 'rgba(0,200,83,0.04)',
          display: 'flex', alignItems: 'center', gap: 18
        }}>
          <span className="f-eyebrow f-eyebrow--accent">bridge</span>
          <span className="f-cap" style={{ fontSize: 12.5, flex: 1 }}>
            The circuit breaker&apos;s <span className="f-mono">before_call</span> computes the two boolean inputs and
            <em> delegates </em> the decision to <span className="f-mono">gate_decision</span>. Because the production
            path goes through the verified function, the proof binds to the shipped code &mdash; not to a separate model.
          </span>
        </div>
      </div>

      <div className="fig-footer">
        <span><span className="fig-num"></span> &nbsp;&middot;&nbsp; Two-level fail-closed proof &mdash; Z3 over model, Kani over Rust</span>
        <span className="fig-src">Dobrin · Unfireable Safety Kernel · §6.4</span>
      </div>
    </div>);

}

const texStyle = {
  margin: 0,
  padding: '12px 14px',
  background: 'var(--navy-950)',
  border: '1px solid var(--border-default)',
  borderRadius: 3,
  fontFamily: 'var(--font-mono)',
  fontSize: 12,
  color: 'var(--fg-secondary)',
  lineHeight: 1.55,
  whiteSpace: 'pre',
  overflow: 'hidden'
};

function ProofColumn({ badge, level, scope, content }) {
  return (
    <div style={{
      flex: 1,
      display: 'flex', flexDirection: 'column', gap: 12,
      padding: '18px 20px',
      border: '1px solid var(--border-default)',
      borderRadius: 4,
      background: 'var(--navy-800)',
      boxShadow: 'var(--shadow-inset-top)'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
        <div>
          <div className="f-eyebrow f-eyebrow--accent">{level}</div>
          <div style={{ fontSize: 14, color: 'var(--fg-secondary)', marginTop: 4 }}>{scope}</div>
        </div>
        <span className="f-tag f-tag--accent">{badge}</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {content}
      </div>
    </div>);

}

function KaniHarness({ name }) {
  return (
    <div style={{
      padding: '7px 10px',
      border: '1px solid var(--border-default)',
      borderLeft: '3px solid var(--accent)',
      borderRadius: 3,
      background: 'rgba(0,200,83,0.04)',
      fontFamily: 'var(--font-mono)',
      fontSize: 11.5,
      color: 'var(--fg-secondary)',
      lineHeight: 1.3
    }}>
      <span style={{ color: 'var(--accent)' }}>fn </span>{name}
    </div>);

}

/* ---------------------------------------------------------------------
   Figure 8 — Transparency log
   Append-only hash chain. Operator-signed root. External verifier off
   to the side. Detection (not prevention) is the property.
--------------------------------------------------------------------- */
function Figure8TransparencyLog() {
  const entries = [
  { i: 'n−2', decision: 'authorize · tool=mailer', outcome: 'allow', chain: '0x9f3a…' },
  { i: 'n−1', decision: 'authorize · tool=billing', outcome: 'allow', chain: '0x4c11…' },
  { i: 'n', decision: 'authorize · tool=deploy', outcome: 'allow', chain: '0xe682…' }];


  return (
    <div className="fig">
      <div className="fig-header">
        <div className="fig-eyebrow">TRANSPARENCY LOG</div>
        <h2 className="fig-title">A compromised kernel cannot quietly start lying.</h2>
        <p className="fig-sub">
          Every allowed action appends a signed entry. Any third party with the operator public key
          can replay the log, recompute the decision, and detect divergence &mdash; the same property
          Certificate Transparency delivers for the CA ecosystem.
        </p>
      </div>

      <div className="fig-body" style={{ flexDirection: 'column' }}>
        <div style={{ display: 'flex', gap: 28, flex: 1 }}>
          {/* Left: log chain */}
          <div style={{ flex: '0 0 56%', display: 'flex', flexDirection: 'column', gap: 0 }}>
            {/* signed tree head */}
            <div style={{
              padding: '14px 18px',
              border: '2px solid rgba(0,200,83,0.55)',
              borderRadius: 4,
              background: 'rgba(0,200,83,0.06)'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                <div>
                  <div className="f-eyebrow f-eyebrow--accent">signed tree head</div>
                  <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--white)', marginTop: 4 }}>STH at size <span className="f-mono">n</span></div>
                </div>
                <KeyIconSigned />
              </div>
              <div className="f-mono" style={{ fontSize: 11, color: 'var(--fg-muted)', marginTop: 8 }}>
                root_hash = 0xa3d1…  ·  signed by operator key (Ed25519)
              </div>
            </div>

            <LogConnector />

            {entries.map((e, i) =>
            <React.Fragment key={i}>
                <LogEntry idx={e.i} decision={e.decision} outcome={e.outcome} chain={e.chain} />
                {i < entries.length - 1 && <LogChainLink />}
              </React.Fragment>
            )}

            <div className="f-cap" style={{
              fontSize: 11, color: 'var(--fg-muted)', marginTop: 10,
              fontFamily: 'var(--font-mono)', letterSpacing: 0
            }}>
              chain_hash<sub style={{ fontSize: 9 }}>i</sub> = H(chain_hash<sub style={{ fontSize: 9 }}>i−1</sub> ‖ entry<sub style={{ fontSize: 9 }}>i</sub>)
            </div>
          </div>

          {/* Right: actors */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 14 }}>
            <ActorBox
              tone="brand"
              title="Operator"
              role="signs the tree head"
              points={['holds private key (HSM / token / threshold)', 'rotates without restarting the kernel', 'never visible to the agent']} />
            
            <ActorBox
              tone="accent"
              title="External verifier"
              role="any third party with the public key"
              points={['recomputes expected decision from policy + request', 'compares to the kernel-signed entry', 'divergence = evidence of compromise']} />
            
            <div style={{
              padding: '14px 16px',
              border: '1px dashed var(--border-strong)',
              borderRadius: 4,
              background: 'rgba(255,255,255,0.015)'
            }}>
              <div className="f-eyebrow" style={{ marginBottom: 6 }}>property</div>
              <div className="f-cap" style={{ fontSize: 12.5, lineHeight: 1.5 }}>
                <span style={{ color: 'var(--accent)', fontWeight: 700 }}>Detection, not prevention.</span>{' '}
                A single component compromise no longer produces complete bypass &mdash; it produces
                a verifiable lie.
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="fig-footer">
        <span><span className="fig-num"></span> &nbsp;&middot;&nbsp; Append-only · operator-signed · externally verifiable</span>
        <span className="fig-src">Dobrin · Unfireable Safety Kernel · §4–§5</span>
      </div>
    </div>);

}

function LogEntry({ idx, decision, outcome, chain }) {
  return (
    <div style={{
      padding: '12px 16px',
      border: '1px solid var(--border-default)',
      borderRadius: 4,
      background: 'var(--navy-800)',
      display: 'grid',
      gridTemplateColumns: '60px 1fr auto',
      gap: 12,
      alignItems: 'center',
      boxShadow: 'var(--shadow-inset-top)'
    }}>
      <span className="f-mono" style={{ fontSize: 12, color: 'var(--fg-muted)' }}>entry {idx}</span>
      <div>
        <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--white)' }}>{decision}</div>
        <div className="f-mono" style={{ fontSize: 11, color: 'var(--fg-muted)', marginTop: 3 }}>
          chain_hash = {chain}
        </div>
      </div>
      <span className="f-tag f-tag--accent">{outcome}</span>
    </div>);

}

function LogChainLink() {
  return (
    <div style={{ display: 'flex', justifyContent: 'center', padding: '4px 0' }}>
      <svg width="22" height="18" viewBox="0 0 22 18">
        <line x1="11" y1="0" x2="11" y2="12" stroke="var(--fg-muted)" strokeWidth="1.5" strokeDasharray="2 2" />
        <path d="M6 12 L11 18 L16 12 Z" fill="var(--fg-muted)" />
      </svg>
    </div>);

}

function LogConnector() {
  return (
    <div style={{ display: 'flex', justifyContent: 'center', padding: '8px 0' }}>
      <svg width="18" height="22" viewBox="0 0 18 22">
        <line x1="9" y1="0" x2="9" y2="16" stroke="var(--accent)" strokeWidth="1.5" />
        <path d="M4 16 L9 22 L14 16 Z" fill="var(--accent)" />
      </svg>
    </div>);

}

function KeyIconSigned() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
      <circle cx="8" cy="12" r="3.5" stroke="var(--accent)" strokeWidth="1.7" />
      <path d="M11.5 12 L21 12 L21 16 M17 12 L17 15" stroke="var(--accent)" strokeWidth="1.7" />
    </svg>);

}

function ActorBox({ tone, title, role, points }) {
  const c = tone === 'brand' ? {
    color: 'var(--brand)', border: 'rgba(225,59,112,0.45)', bg: 'rgba(225,59,112,0.05)'
  } : {
    color: 'var(--accent)', border: 'rgba(0,200,83,0.45)', bg: 'rgba(0,200,83,0.04)'
  };
  return (
    <div style={{
      padding: '14px 16px',
      border: `1px solid ${c.border}`,
      borderRadius: 4,
      background: c.bg
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
        <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--white)' }}>{title}</div>
        <span className="f-eyebrow" style={{ color: c.color, fontSize: 10 }}>{role}</span>
      </div>
      <ul style={{ margin: '10px 0 0', paddingLeft: 16, color: 'var(--fg-secondary)', fontSize: 12.5, lineHeight: 1.55 }}>
        {points.map((p, i) => <li key={i}>{p}</li>)}
      </ul>
    </div>);

}

Object.assign(window, {
  Figure5RelatedSystemsMatrix,
  Figure7TwoLevelVerification,
  Figure8TransparencyLog
});