"""Verification module — Track A (functional) and Track B (cryptographic assurance).

Both tracks must pass for overall = pass. Failures are stored, never dropped.
Track B owns KAT vectors and lint rules; other modules may not override its verdict.
"""
