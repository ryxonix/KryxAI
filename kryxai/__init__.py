"""KryxAI - passive cryptographic posture forensics for SMTP/IMAP/POP3.

KryxAI reads captured network traffic, reconstructs mail sessions, detects
STARTTLS downgrade and tampering, validates TLS handshakes and X.509
certificates, scores cryptographic risk, maps findings to the Digital Personal
Data Protection Act 2023, and seals the result into a tamper-evident,
blockchain-anchored evidence chain.

Design rule: nothing in this package ever fabricates a finding, a hash, or a
status. A degraded input yields a degraded, explicitly-labelled result.
"""

__version__ = "0.1.0"
CHAIN_ID = "KryxAIV1"
