# HANDOFF — contractors-suite-by-techguru

## Current state snapshot (Oct 31, 2026 ~16:10 MDT)
- Live demo: https://contractor-crm-suite.techguruofficial.workers.dev/ (Worker `contractor-crm-suite`)
- Repo: TechGuruServices/contractors-suite-by-techguru, branch `main`, source `src/index.js`
- Latest change: Elevate renames + PDF printout + file uploads + business branding + 14-day trial + PWA packaging (see below), pushed by TECHGURU-MUSE

## HANDOFF: 2026-10-31 ~16:10 MDT (TECHGURU-MUSE)
Feature batch per Lucas — Elevate renames, PDF/file uploads, business branding, 14-day trial, PWA packaging:
- **Elevate renames**: "Customer Matrix"→"Elevate CRM", "Field Time Tracker"→"Elevate Time", "Review Dispatch"→"Elevate Reviews", "Admin Panel"→"Elevate Admin" (nav, headers, login subtitle, paywall copy).
- **PDF printout**: per-client "Work Order PDF" (TECHGURU-branded, Print/Share/Email/Save via jsPDF) + admin "Export PDF" timesheet report. Email uses mailto (cannot attach files — PDF auto-downloads for manual attach; stated to Lucas).
- **Crew file uploads**: per-client "Files" button → upload modal (images/PDF/Word/text, 10MB cap) backed by R2 bucket `contractor-crm-uploads` + D1 `uploads` table. Routes: POST/GET /api/uploads, GET/DELETE /api/uploads/:id (auth-required). Requires worker R2 binding UPLOADS→contractor-crm-uploads at deploy.
- **Business branding**: per-user logo upload (admin "Business branding" card, client-side downscale to 512px, 2MB cap) stored in R2 `branding/{user_id}/logo` + D1 `branding` table. Logo appears on login/paywall tiles and in PDF headers. Routes: POST/GET /api/branding/logo, GET /api/branding/logo/file, DELETE /api/branding/logo (auth-required). Same UPLOADS binding.
- **14-day free trial**: users.trial_ends_at (lazy ALTER); register grants 14 days; login grants trial to pre-existing NULL accounts; JWT + responses carry trial_active; frontend gate allows subscribed OR trial_active; paywall shows "trial has ended" messaging; server-side 403 enforcement on all non-auth protected routes; GET /api/auth/me for status refresh on app init.
- **PWA packaging**: /manifest.json, /sw.js (network-first, API never cached), /icons/* + /apple-touch-icon.png served from R2 `pwa/` prefix; manifest link + theme-color + SW registration in HTML head/init.
- Pricing decided by Lucas: **$9.99/mo after 14-day free trial**. Stripe product not yet created (Stripe needs reauthorization).
- Lucas does his own trailers/demos — Muse delivers screenshots only (no videos).
- Microsoft Store PWA submission in progress (Lucas ordered end-to-end): needs deploy to TECHGURU domain + PWABuilder/Partner Center (phone approval).

## HANDOFF: 2026-10-31 ~08:10 MDT (TECHGURU-MUSE)
Rebrand + subscription gate, per Lucas:
- Dropped the emerald-green accent system; primary accent is now safety orange (#f97316, dim #ea580c) with warm charcoal theme to match contractor/construction audience. CSS vars renamed --accent-emerald→--accent-brand etc. TECHGURU footer gradient and login "by TECHGURU" brandline added; page title "Contractor Pro CRM Suite · by TECHGURU".
- Subscription gate (not free): users table gains `is_subscribed` (lazy ALTER on login); login response includes `subscribed`; unsubscribed users see a paywall view with Subscribe CTA (env SUBSCRIBE_URL, falls back to book.techguruofficial.us) and optional 60s demo video link (env DEMO_VIDEO_URL). New registrations default to unsubscribed. New admin endpoint POST /api/admin/subscribe {email} activates a user (admin only).
- Login page no longer prefills demo credentials; footer now "Subscription required · Secured with PBKDF2-SHA256".
- Demo account admin@contractor.local must be activated via /api/admin/subscribe after deploy (or it will see the paywall).
- Seeded demo data (4 fictional DEMO clients, $11,600 pipeline) lives in the production D1 `contractor_db`, untouched by this change.
- wrangler.json still carries placeholder database_id/JWT_SECRET — do NOT deploy from this file alone; production bindings must be preserved at deploy time.
