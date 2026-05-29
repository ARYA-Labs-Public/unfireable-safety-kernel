/* Unfireable Safety Kernel — Paper Figures — main composition */
const { DesignCanvas, DCSection, DCArtboard } = window;
const {
  Figure1InProcessVsOutOfProcess,
  Figure3AlignmentLayers,
  Figure6EscapableTaxonomy,
} = window;
const {
  Figure2FourSeams,
  Figure4ChainOfTrust,
  Figure9StaticVsDynamicRoutes,
} = window;
const {
  Figure5RelatedSystemsMatrix,
  Figure7TwoLevelVerification,
  Figure8TransparencyLog,
} = window;

function App() {
  return (
    <DesignCanvas title="Unfireable Safety Kernel — Paper Figures" subtitle="Nine figures for Execution-Time AI Alignment (Dobrin, 2026)">
      <DCSection id="conceptual" title="Conceptual" subtitle="Editorial figures — the central architectural argument">
        <DCArtboard id="fig1" label="Fig 1 · In-process vs out-of-process" width={1400} height={820}>
          <Figure1InProcessVsOutOfProcess />
        </DCArtboard>
        <DCArtboard id="fig3" label="Fig 3 · Three alignment layers" width={1200} height={820}>
          <Figure3AlignmentLayers />
        </DCArtboard>
        <DCArtboard id="fig6" label="Fig 6 · Escapable AI systems" width={1300} height={980}>
          <Figure6EscapableTaxonomy />
        </DCArtboard>
      </DCSection>

      <DCSection id="architecture" title="Architecture" subtitle="Technical diagrams — how the kernel sits on the only path">
        <DCArtboard id="fig2" label="Fig 2 · Four-seam architecture" width={1200} height={1220}>
          <Figure2FourSeams />
        </DCArtboard>
        <DCArtboard id="fig4" label="Fig 4 · Chain of trust" width={1500} height={660}>
          <Figure4ChainOfTrust />
        </DCArtboard>
        <DCArtboard id="fig9" label="Fig 9 · Static vs dynamic routes" width={1400} height={780}>
          <Figure9StaticVsDynamicRoutes />
        </DCArtboard>
      </DCSection>

      <DCSection id="verification" title="Verification &amp; Evidence" subtitle="Proofs, audit, and where the kernel improves on adjacent systems">
        <DCArtboard id="fig5" label="Fig 5 · Related systems matrix" width={1400} height={1040}>
          <Figure5RelatedSystemsMatrix />
        </DCArtboard>
        <DCArtboard id="fig7" label="Fig 7 · Two-level fail-closed proof" width={1300} height={960}>
          <Figure7TwoLevelVerification />
        </DCArtboard>
        <DCArtboard id="fig8" label="Fig 8 · Transparency log" width={1100} height={800}>
          <Figure8TransparencyLog />
        </DCArtboard>
      </DCSection>
    </DesignCanvas>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
