/* =====================================================================
   CONCEPTUAL FIGURES — 1, 3, 6
   Editorial diagrams. Lean on contrast and scale to carry the argument.
   ===================================================================== */

/* ---------------------------------------------------------------------
   Figure 1 — In-process vs out-of-process controls
   Two side-by-side architectures. Left: the current mistake (everything
   in one address space). Right: the kernel architecture (process boundary
   between agent and controls).
--------------------------------------------------------------------- */
function Figure1InProcessVsOutOfProcess() {
  return (
    <div className="fig">
      <div className="fig-header">
        <div className="fig-eyebrow">THE ARCHITECTURAL MISTAKE, AND THE FIX</div>
        <h2 className="fig-title">A control the controlled process can reach is not a control. It is a request.</h2>
        <p className="fig-sub">
          Every &ldquo;guardrail&rdquo; shipping in production today lives in the same address space as the agent it
          is supposed to constrain. The agent can read it, replace it, or refuse to invoke it.
        </p>
      </div>

      <div className="fig-body" style={{ gap: 28 }}>
        {/* ─────────── LEFT: the mistake ─────────── */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
            <span className="f-eyebrow f-eyebrow--danger">A · Today &mdash; in-process &ldquo;safety&rdquo;</span>
            <span className="f-tag f-tag--danger">request, not control</span>
          </div>

          <div style={{
            position: 'relative',
            flex: 1,
            border: '2px dashed rgba(239,68,68,0.55)',
            borderRadius: 6,
            padding: '34px 26px 28px',
            background: 'linear-gradient(180deg, rgba(239,68,68,0.04) 0%, rgba(239,68,68,0.015) 100%)',
            display: 'flex', flexDirection: 'column', gap: 20
          }}>
            <div style={{
              position: 'absolute', top: -11, left: 22,
              padding: '2px 10px',
              background: 'var(--navy-900)',
              fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
              letterSpacing: '0.16em', textTransform: 'uppercase',
              color: 'var(--danger)', whiteSpace: 'nowrap'
            }}>
              one address space &middot; one trust boundary
            </div>

            <div className="f-card f-card--danger" style={{ background: 'rgba(239,68,68,0.08)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--white)' }}>Agent / LLM</div>
                  <div className="f-cap" style={{ marginTop: 4 }}>continuously active principal &middot; tool-using</div>
                </div>
                <span className="f-tag f-tag--danger">attacker</span>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <ControlItem name="System prompt" mech="readable string in context" />
              <ControlItem name="Output filter" mech="importable / monkey-patchable" />
              <ControlItem name="Guardrail library" mech="sys.modules — one line replaces it" />
              <ControlItem name="Moderation API" mech="agent chooses whether to call" />
            </div>

            <div style={{ marginTop: 'auto', display: 'flex', alignItems: 'center', gap: 10 }}>
              <ArrowReach />
              <div className="f-cap" style={{ fontSize: 12, color: 'var(--danger)' }}>
                Every control is reachable from the agent. Prompt injection &rarr; bypass.
              </div>
            </div>
          </div>
        </div>

        {/* ─────────── RIGHT: the architecture ─────────── */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
            <span className="f-eyebrow f-eyebrow--accent">B · The kernel architecture</span>
            <span className="f-tag f-tag--accent">control, not request</span>
          </div>

          <div style={{
            flex: 1, display: 'grid',
            gridTemplateColumns: '1fr 38px 1fr',
            gap: 0, alignItems: 'stretch'
          }}>
            {/* agent side */}
            <div style={{
              border: '2px dashed rgba(225,59,112,0.5)',
              borderRadius: 6, padding: '34px 22px 22px',
              background: 'rgba(225,59,112,0.035)',
              position: 'relative',
              display: 'flex', flexDirection: 'column', gap: 14
            }}>
              <div style={{
                position: 'absolute', top: -11, left: 22,
                padding: '2px 10px', background: 'var(--navy-900)',
                fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
                letterSpacing: '0.16em', textTransform: 'uppercase',
                color: 'var(--brand)', whiteSpace: 'nowrap'
              }}>
                untrusted process
              </div>
              <div className="f-card f-card--brand" style={{ background: 'rgba(225,59,112,0.07)' }}>
                <div style={{ fontSize: 17, fontWeight: 700, color: 'var(--white)' }}>Agent / LLM</div>
                <div className="f-cap" style={{ marginTop: 4 }}>same model. same prompts. same risk surface.</div>
              </div>
              <div className="f-card f-card--dashed" style={{ padding: '14px 16px' }}>
                <div className="f-eyebrow" style={{ fontSize: 10 }}>holds only</div>
                <div style={{ fontSize: 14, color: 'var(--fg-secondary)', marginTop: 6, lineHeight: 1.5 }}>
                  an identity assertion + a request to authorize.
                </div>
              </div>
              <div style={{ marginTop: 'auto' }} className="f-cap">
                Can ask. Cannot read, write, or replace the kernel.
              </div>
            </div>

            {/* wall + channel */}
            <ProcessWall />

            {/* kernel side */}
            <div style={{
              border: '2px solid rgba(0,200,83,0.55)',
              borderRadius: 6, padding: '34px 22px 22px',
              background: 'rgba(0,200,83,0.04)',
              position: 'relative',
              display: 'flex', flexDirection: 'column', gap: 14
            }}>
              <div style={{
                position: 'absolute', top: -11, left: 22,
                padding: '2px 10px', background: 'var(--navy-900)',
                fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
                letterSpacing: '0.16em', textTransform: 'uppercase',
                color: 'var(--accent)', whiteSpace: 'nowrap'
              }}>
                separate process
              </div>
              <div className="f-card f-card--accent" style={{ background: 'rgba(0,200,83,0.08)' }}>
                <div style={{ fontSize: 17, fontWeight: 700, color: 'var(--white)' }}>Unfireable Safety Kernel</div>
                <div className="f-cap" style={{ marginTop: 4 }}>compiled Rust &middot; static routes &middot; <span className="f-mono">#![forbid(unsafe_code)]</span></div>
              </div>
              <div className="f-card" style={{ padding: '14px 16px' }}>
                <div className="f-eyebrow f-eyebrow--accent" style={{ fontSize: 10 }}>holds</div>
                <ul style={{ margin: '6px 0 0', paddingLeft: 16, color: 'var(--fg-secondary)', fontSize: 13, lineHeight: 1.6 }}>
                  <li>policy &middot; signing key &middot; decision logic</li>
                  <li>append-only log of every allowed action</li>
                </ul>
              </div>
              <div style={{ marginTop: 'auto' }} className="f-cap">
                <span style={{ color: 'var(--accent)' }}>Operator</span> deploys, signs, and rotates. Agent has no operation that reaches here.
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="fig-footer">
        <span><span className="fig-num"></span> &nbsp;&middot;&nbsp; The architectural mistake, and the fix</span>
        <span className="fig-src">Dobrin · Unfireable Safety Kernel · §1–§3</span>
      </div>
    </div>);

}

function ControlItem({ name, mech }) {
  return (
    <div style={{
      padding: '12px 14px',
      border: '1px solid var(--border-default)',
      borderLeft: '3px solid var(--danger)',
      borderRadius: 3,
      background: 'rgba(255,255,255,0.015)'
    }}>
      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--fg-primary)' }}>{name}</div>
      <div className="f-mono" style={{ fontSize: 11, color: 'var(--fg-muted)', marginTop: 4 }}>{mech}</div>
    </div>);

}

function ArrowReach() {
  return (
    <svg className="f-arrow-svg" width="44" height="20" viewBox="0 0 44 20">
      <path d="M2 10 L36 10" stroke="var(--danger)" strokeWidth="1.5" strokeDasharray="3 3" />
      <path d="M30 4 L40 10 L30 16 Z" className="head" fill="var(--danger)" />
    </svg>);

}

function ProcessWall() {
  // a 38px-wide column showing the process boundary and the single channel
  return (
    <div style={{ position: 'relative', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <div style={{
        position: 'absolute', top: 0, bottom: 0, left: '50%',
        width: 4, transform: 'translateX(-50%)',
        background: 'repeating-linear-gradient(0deg, var(--border-strong) 0 6px, transparent 6px 12px)'
      }} />
      <svg width="38" height="100%" viewBox="0 0 38 220" preserveAspectRatio="none" style={{ position: 'relative' }}>
        {/* request arrow */}
        <path d="M2 70 L34 70" stroke="var(--fg-muted)" strokeWidth="1.5" fill="none" />
        <path d="M28 65 L36 70 L28 75 Z" fill="var(--fg-muted)" />
        {/* response arrow */}
        <path d="M36 150 L4 150" stroke="var(--accent)" strokeWidth="1.5" fill="none" />
        <path d="M10 145 L2 150 L10 155 Z" fill="var(--accent)" />
      </svg>
      <div className="f-mono" style={{
        position: 'absolute', top: 38, left: '50%', transform: 'translateX(-50%)',
        fontSize: 9, color: 'var(--fg-muted)', whiteSpace: 'nowrap',
        background: 'var(--navy-900)', padding: '0 4px'
      }}>authorize()</div>
      <div className="f-mono" style={{
        position: 'absolute', top: 132, left: '50%', transform: 'translateX(-50%)',
        fontSize: 9, color: 'var(--accent)', whiteSpace: 'nowrap',
        background: 'var(--navy-900)', padding: '0 4px'
      }}>signed token</div>
    </div>);

}

/* ---------------------------------------------------------------------
   Figure 3 — Three layers of AI alignment
   Stacked bands: training-time, inference-time, execution-time.
   For each: where it runs, what it shapes, who delivers, robustness mode.
--------------------------------------------------------------------- */
function Figure3AlignmentLayers() {
  return (
    <div className="fig">
      <div className="fig-header">
        <div className="fig-eyebrow">THE AI ALIGNMENT STACK</div>
        <h2 className="fig-title">Three layers of alignment. Only the top one is architectural.</h2>
        <p className="fig-sub">
          Training and inference shape <em>what the model produces</em>, probabilistically.
          Execution-time alignment governs <em>what the model is permitted to do</em>, architecturally.
          A misaligned agent that reaches the tool-call stage has, by definition, already passed everything below.
        </p>
      </div>

      <div className="fig-body" style={{ flexDirection: 'column', gap: 0 }}>
        <AlignLayer
          tier="execution"
          eyebrow="Execution-time AI alignment"
          where="operator boundary &middot; out-of-process kernel"
          shapes="what the model is permitted to do"
          deliverer="Operator"
          robustness="Architectural"
          robustnessNote="proved over every input"
          mechanisms={['process-separated kernel', 'pre-action enforcement', 'fail-closed at request + system', 'signed transparency log']}
          accent="accent"
          dim={1} />
        
        <AlignLayer
          tier="inference"
          eyebrow="Inference-time alignment"
          where="model wrapper &middot; in-process"
          shapes="what the model is permitted to emit"
          deliverer="Model wrapper / app"
          robustness="Probabilistic"
          robustnessNote="bounded by what we can measure"
          mechanisms={['system prompts', 'output filters', 'content moderation', 'guardrail libraries']}
          accent="muted"
          dim={0.65} />
        
        <AlignLayer
          tier="training"
          eyebrow="Training-time alignment"
          where="model provider &middot; in-weights"
          shapes="what the model is likely to produce"
          deliverer="Model provider"
          robustness="Probabilistic"
          robustnessNote="bounded by what we can measure"
          mechanisms={['RLHF', 'Constitutional AI', 'DPO / RLAIF', 'red-teaming']}
          accent="muted"
          dim={0.5}
          last />
        
      </div>

      <div className="fig-footer">
        <span><span className="fig-num"></span> &nbsp;&middot;&nbsp; The alignment stack &mdash; execution-time is the upper layer</span>
        <span className="fig-src">Dobrin · Unfireable Safety Kernel · §8.1</span>
      </div>
    </div>);

}

function AlignLayer({ eyebrow, where, shapes, deliverer, robustness, robustnessNote, mechanisms, accent, dim, last }) {
  const accentColor = accent === 'accent' ? 'var(--accent)' : 'var(--fg-muted)';
  return (
    <div style={{
      position: 'relative',
      display: 'grid',
      gridTemplateColumns: '270px 1fr 220px',
      gap: 28,
      padding: '24px 22px',
      borderTop: '1px solid var(--border-default)',
      borderBottom: last ? '1px solid var(--border-default)' : 'none',
      background: accent === 'accent' ?
      'linear-gradient(90deg, rgba(0,200,83,0.07) 0%, rgba(0,200,83,0) 65%)' :
      'rgba(255,255,255,0.01)',
      opacity: dim
    }}>
      {/* left band — eyebrow + where */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
          letterSpacing: '0.16em', textTransform: 'uppercase',
          color: accentColor
        }}>{eyebrow}</div>
        <div className="f-mono" style={{ fontSize: 12, color: 'var(--fg-muted)' }}>{where}</div>
        <div style={{ fontSize: 13, color: 'var(--fg-secondary)', marginTop: 4 }}>shapes <span style={{ color: 'var(--white)' }}>{shapes}</span></div>
      </div>

      {/* middle — mechanisms */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignContent: 'center' }}>
        {mechanisms.map((m, i) =>
        <span key={i} className={'f-tag ' + (accent === 'accent' ? 'f-tag--accent' : 'f-tag--ghost')}>
            {m}
          </span>
        )}
      </div>

      {/* right — robustness */}
      <div style={{ textAlign: 'right', display: 'flex', flexDirection: 'column', gap: 6 }}>
        <div className="f-eyebrow" style={{ fontSize: 10 }}>delivered by</div>
        <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--white)' }}>{deliverer}</div>
        <div style={{
          marginTop: 8,
          fontSize: 13, fontWeight: 700,
          color: accent === 'accent' ? 'var(--accent)' : 'var(--fg-muted)'
        }}>{robustness}</div>
        <div className="f-cap" style={{ fontSize: 11 }}>{robustnessNote}</div>
      </div>
    </div>);

}

/* ---------------------------------------------------------------------
   Figure 6 — Escapable AI systems taxonomy
   Four classes per §6.1. 2×2 grid with progressively heavier implications.
--------------------------------------------------------------------- */
function Figure6EscapableTaxonomy() {
  const classes = [
  {
    tag: 'Class I · canonical',
    name: 'Tool-using agents',
    reach: 'runtime hosts the controls',
    example: 'the example this paper directly addresses',
    kernel: 'Kernel architecture applies directly',
    kernelTone: 'accent'
  },
  {
    tag: 'Class II',
    name: 'Code-generating systems with execution access',
    reach: 'generated code reaches into the runtime that executes it',
    example: 'model emits code · runtime executes code · system loops',
    kernel: 'Authorization must live outside the address space the generated code runs in',
    kernelTone: 'accent'
  },
  {
    tag: 'Class III',
    name: 'Self-modifying systems · RSI loops',
    reach: 'system modifies own weights, prompts, scaffolding, evaluation criteria',
    example: 'recursive self-improvement &middot; auto-tuning agents',
    kernel: 'Kernel is necessary but not sufficient — policy-modification surface needs its own discipline',
    kernelTone: 'warn'
  },
  {
    tag: 'Class IV',
    name: 'Multi-agent ensembles',
    reach: 'one agent\u2019s actions weaken another agent\u2019s controls',
    example: 'agent A creates conditions under which agent B\u2019s policy no longer applies',
    kernel: 'Per-agent action surface covered; cross-agent emergent escape needs separate analysis',
    kernelTone: 'warn'
  }];


  return (
    <div className="fig">
      <div className="fig-header">
        <div className="fig-eyebrow">THE GENERAL CATEGORY</div>
        <h2 className="fig-title">Agents are the visible case of a broader class: escapable AI systems.</h2>
        <p className="fig-sub">
          The load-bearing property is not &ldquo;agent.&rdquo; It is reach into the runtime that hosts the controls.
          Any system with that reach is escapable; the kernel architecture applies, with increasing additional
          discipline as the reach widens.
        </p>
      </div>

      <div className="fig-body" style={{ flexDirection: 'column', gap: 0 }}>
        {/* legend */}
        <div style={{ display: 'flex', gap: 18, alignItems: 'center', paddingBottom: 14 }}>
          <span className="f-eyebrow" style={{ fontSize: 10 }}>kernel coverage</span>
          <span className="f-tag f-tag--accent">applies directly</span>
          <span className="f-tag" style={{ color: 'var(--warn)', borderColor: 'rgba(245,158,11,0.4)', background: 'rgba(245,158,11,0.06)' }}>necessary but not sufficient</span>
        </div>
        <div style={{ flex: 1, display: 'grid', gridTemplateColumns: '1fr 1fr', gridTemplateRows: '1fr 1fr', gap: 14 }}>
          {classes.map((c, i) => <EscapableCard key={i} {...c} />)}
        </div>
      </div>

      <div className="fig-footer">
        <span><span className="fig-num"></span> &nbsp;&middot;&nbsp; Escapable AI systems &mdash; agents are the worked example</span>
        <span className="fig-src">Dobrin · Unfireable Safety Kernel · §8.2</span>
      </div>
    </div>);

}

function EscapableCard({ tag, name, reach, example, kernel, kernelTone }) {
  const tone = kernelTone === 'accent' ? {
    color: 'var(--accent)', bg: 'rgba(0,200,83,0.06)', border: 'rgba(0,200,83,0.4)'
  } : {
    color: 'var(--warn)', bg: 'rgba(245,158,11,0.06)', border: 'rgba(245,158,11,0.4)'
  };
  return (
    <div style={{
      border: '1px solid var(--border-default)',
      borderRadius: 4,
      background: 'var(--navy-800)',
      padding: '20px 22px',
      display: 'flex', flexDirection: 'column', gap: 14,
      boxShadow: 'var(--shadow-inset-top)'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
        <span className="f-eyebrow">{tag}</span>
      </div>
      <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--white)', lineHeight: 1.15 }}>{name}</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 4 }}>
        <KV label="reach" value={reach} />
        <KV label="example" value={<span dangerouslySetInnerHTML={{ __html: example }} />} />
      </div>
      <div style={{
        marginTop: 'auto',
        padding: '10px 12px',
        borderRadius: 3,
        border: `1px solid ${tone.border}`,
        background: tone.bg,
        color: tone.color,
        fontSize: 12.5,
        fontWeight: 600,
        lineHeight: 1.45
      }}>{kernel}</div>
    </div>);

}

function KV({ label, value }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '80px 1fr', gap: 12 }}>
      <div className="f-eyebrow" style={{ fontSize: 10, paddingTop: 2 }}>{label}</div>
      <div style={{ fontSize: 13.5, color: 'var(--fg-secondary)', lineHeight: 1.45 }}>{value}</div>
    </div>);

}

Object.assign(window, {
  Figure1InProcessVsOutOfProcess,
  Figure3AlignmentLayers,
  Figure6EscapableTaxonomy
});