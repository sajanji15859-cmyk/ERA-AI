"""Web chat dashboard (Phase 3E).

The dashboard is a dependency-free static frontend (``static/``) served by the
FastAPI app itself at ``/`` — same origin as the API, so the Phase 2A
authentication model applies unchanged. The UI is a thin, mobile-first client
over the authenticated agent chat + confirmation endpoints; it never bypasses
auth, authorization, the permission engine, or the approval gate.
"""
