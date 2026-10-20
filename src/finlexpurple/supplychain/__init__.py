"""Supply-chain testing module (Phase 13; decisions.md §20, §25).

Tests the dependency surface a target trusts. Known-vulnerability matching is
delegated to wrapped best-of-breed scanners (OSV-Scanner, pip-audit) whose real
output is normalized into the Finding schema — never paraphrased (§20). The
original engineering here is the fintech-specific detection competitors lack:
slopsquatting / hallucinated dependencies (Differentiator 6), payment-SDK
typosquats (Differentiator 7), and secrets detection. Online and offline modes
are both supported and always labeled honestly (§25).
"""
