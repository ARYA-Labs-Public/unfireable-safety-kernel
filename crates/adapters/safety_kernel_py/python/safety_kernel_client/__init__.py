"""safety_kernel_client — Python binding for the Safety Kernel Rust primitives.

The public surface is the *real* Rust code (compiled via PyO3), not a
reimplementation:

- ``params_fingerprint(params: dict) -> str`` — the canonical
  ``sha256_hex(stable_json(params))`` the kernel recomputes server-side.
  Byte-identical to the Rust ``params_fingerprint``.
- ``PinnedKeyVerifier`` — the offline Ed25519 receipt verifier. Verify a
  kernel authorization token against a pinned public key with **no network
  call**; any failure raises (fail-closed).

Re-import-safe shim (mirrors the internal arya-core-py pattern): bind the
compiled extension submodule to a real local name (``_ext``) before
re-exporting, so popping this module from ``sys.modules`` cannot NameError the
shim. The ``module-name = "safety_kernel_client"`` maturin override names the
``.so``; this hand-written init (shipped via ``python-source``) makes re-import
safe and gives a clear error when the extension was never built.
"""
from __future__ import annotations

try:
    from . import safety_kernel_client as _ext  # compiled submodule → real local name
    from .safety_kernel_client import *  # noqa: F401,F403 — re-export compiled symbols

    __doc__ = _ext.__doc__ or __doc__
    __all__ = getattr(
        _ext, "__all__", [n for n in dir(_ext) if not n.startswith("_")]
    )
    __version__ = getattr(_ext, "__version__", "0.0.0")
except ImportError as exc:  # extension not built — pure-source checkout
    raise ImportError(
        "safety_kernel_client: compiled extension not found. Install the wheel "
        "(`pip install safety-kernel-client`) or build it with `maturin develop` "
        "from crates/adapters/safety_kernel_py."
    ) from exc
