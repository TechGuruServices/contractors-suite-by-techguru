# HANDOFF — contractors-suite-by-techguru

## Current state snapshot (Oct 31, 2026 ~08:10 MDT)
- Live demo: https://contractor-crm-suite.techguruofficial.workers.dev/ (Worker `contractor-crm-suite`)
- Repo: TechGuruServices/contractors-suite-by-techguru, branch `main`, source `src/index.js`
- Latest change: UI rebrand + subscription gate (see below), pushed by TECHGURU-MUSE

## HANDOFF: 2026-10-31 ~08:10 MDT (TECHGURU-MUSE)
Rebrand + subscription gate, per Lucas:
- Dropped the emerald-green accent system; primary accent is now safety orange (#f97316, dim #ea580c) with warm charcoal theme to match contractor/construction audience. CSS vars renamed --accent-emerald→--accent-brand etc. TECHGURU footer gradient and login "by TECHGURU" brandline added; page title "Contractor Pro CRM Suite · by TECHGURU".
- Subscription gate (not free): users table gains `is_subscribed` (lazy ALTER on login); login response includes `subscribed`; unsubscribed users see a paywall view with Subscribe CTA (env SUBSCRIBE_URL, falls back to book.techguruofficial.us) and optional 60s demo video link (env DEMO_VIDEO_URL). New registrations default to unsubscribed. New admin endpoint POST /api/admin/subscribe {email} activates a user (admin only).
- Login page no longer prefills demo credentials; footer now "Subscription required · Secured with PBKDF2-SHA256".
- Demo account admin@contractor.local must be activated via /api/admin/subscribe after deploy (or it will see the paywall).
- Seeded demo data (4 fictional DEMO clients, $11,600 pipeline) lives in the production D1 `contractor_db`, untouched by this change.
- wrangler.json still carries placeholder database_id/JWT_SECRET — do NOT deploy from this file alone; production bindings must be preserved at deploy time.
