export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // Global Native CORS Preflight Headers
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS, PUT, DELETE",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // --- CRYPTOGRAPHIC UTILITIES (Web Crypto API) ---
    const cryptoUtils = {
      // Robust PBKDF2 password derivation (Secure native替代 bcrypt)
      async hashPassword(password) {
        const encoder = new TextEncoder();
        const baseKey = await crypto.subtle.importKey(
          "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits", "deriveKey"]
        );
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iterations = 100000;
        
        const derivedKey = await crypto.subtle.deriveKey(
          { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
          baseKey,
          { name: "HMAC", hash: "SHA-256", length: 256 },
          true,
          ["sign"]
        );
        
        const exportedKey = await crypto.subtle.exportKey("raw", derivedKey);
        const hashBuffer = new Uint8Array(exportedKey);
        
        const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
        const hashHex = Array.from(hashBuffer).map(b => b.toString(16).padStart(2, '0')).join('');
        
        return `pbkdf2_sha256$${iterations}$${saltHex}$${hashHex}`;
      },

      async verifyPassword(password, storedHash) {
        const parts = storedHash.split('$');
        if (parts.length !== 4) return false;
        const iterations = parseInt(parts[1], 10);
        const saltHex = parts[2];
        const originalHashHex = parts[3];
        
        const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const encoder = new TextEncoder();
        const baseKey = await crypto.subtle.importKey(
          "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits", "deriveKey"]
        );
        
        const derivedKey = await crypto.subtle.deriveKey(
          { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
          baseKey,
          { name: "HMAC", hash: "SHA-256", length: 256 },
          true,
          ["sign"]
        );
        
        const exportedKey = await crypto.subtle.exportKey("raw", derivedKey);
        const hashBuffer = new Uint8Array(exportedKey);
        const verifyHex = Array.from(hashBuffer).map(b => b.toString(16).padStart(2, '0')).join('');
        
        return verifyHex === originalHashHex;
      },

      // Stateless HMAC JWT Implementation
      async generateJWT(payload, secret) {
        const encoder = new TextEncoder();
        const header = { alg: "HS256", typ: "JWT" };
        const encodedHeader = btoa(JSON.stringify(header)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
        
        // Expiry set to 7 days
        payload.exp = Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60);
        const encodedPayload = btoa(JSON.stringify(payload)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
        
        const tokenInput = `${encodedHeader}.${encodedPayload}`;
        const key = await crypto.subtle.importKey(
          "raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
        );
        const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(tokenInput));
        const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
          .replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
          
        return `${tokenInput}.${encodedSignature}`;
      },

      async verifyJWT(token, secret) {
        try {
          const parts = token.split('.');
          if (parts.length !== 3) return null;
          const [encodedHeader, encodedPayload, encodedSignature] = parts;
          
          const encoder = new TextEncoder();
          const tokenInput = `${encodedHeader}.${encodedPayload}`;
          const key = await crypto.subtle.importKey(
            "raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
          );
          
          // Reconstruct signature bytes safely
          const sigString = atob(encodedSignature.replace(/-/g, "+").replace(/_/g, "/"));
          const sigBytes = new Uint8Array(sigString.length);
          for (let i = 0; i < sigString.length; i++) sigBytes[i] = sigString.charCodeAt(i);
          
          const isValid = await crypto.subtle.verify("HMAC", key, sigBytes, encoder.encode(tokenInput));
          if (!isValid) return null;
          
          const payload = JSON.parse(atob(encodedPayload.replace(/-/g, "+").replace(/_/g, "/")));
          if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) return null; // Expired
          
          return payload;
        } catch {
          return null;
        }
      }
    };

    // --- AUTH MIDDLEWARE GUARDIAN ---
    const getAuthenticatedUser = async (request) => {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
      const token = authHeader.split(" ")[1];
      return await cryptoUtils.verifyJWT(token, env.JWT_SECRET);
    };

    // ==========================================
    // BACKEND API ROUTER ROUTING LOGIC
    // ==========================================
    
    // Auth Endpoint: Register User
    if (url.pathname === "/api/auth/register" && request.method === "POST") {
      try {
        const { name, email, password, role } = await request.json();
        if (!name || !email || !password) return new Response(JSON.stringify({ error: "Missing parameters" }), { status: 400, headers: corsHeaders });
        
        const id = crypto.randomUUID();
        const hashedPassword = await cryptoUtils.hashPassword(password);
        const assignedRole = role === "admin" ? "admin" : "crew"; // Default protection boundary
        
        await env.DB.prepare("INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)")
          .bind(id, name, email, hashedPassword, assignedRole).run();
          
        return new Response(JSON.stringify({ success: true, userId: id }), { status: 201, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      } catch (err) {
        return new Response(JSON.stringify({ error: "User registration failed or email conflict", details: err.message }), { status: 400, headers: corsHeaders });
      }
    }

    // Setup Endpoint: Re-hash the seed admin password so login works
    if (url.pathname === "/api/setup" && request.method === "POST") {
      try {
        const adminUser = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind("admin@contractor.local").first();
        if (!adminUser) return new Response(JSON.stringify({ error: "No admin seed user found" }), { status: 404, headers: corsHeaders });
        
        const newHash = await cryptoUtils.hashPassword("Admin123!");
        await env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ?").bind(newHash, adminUser.id).run();
        return new Response(JSON.stringify({ success: true, message: "Admin password re-hashed successfully" }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      } catch (err) {
        return new Response(JSON.stringify({ error: "Setup failed", details: err.message }), { status: 500, headers: corsHeaders });
      }
    }

    // Auth Endpoint: Login User
    if (url.pathname === "/api/auth/login" && request.method === "POST") {
      try {
        const { email, password } = await request.json();
        const user = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
        if (!user) return new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401, headers: corsHeaders });
        
        let validPassword = await cryptoUtils.verifyPassword(password, user.password_hash);
        
        // Auto-fix: if the stored hash is the static seed placeholder, re-hash it properly
        if (!validPassword && user.password_hash.includes('$salt12345$')) {
          // This is the seed placeholder — rehash with real crypto and try again
          const newHash = await cryptoUtils.hashPassword("Admin123!");
          await env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ?").bind(newHash, user.id).run();
          // Re-verify with new hash only if the provided password is the default
          if (password === "Admin123!") {
            validPassword = true;
          }
        }
        
        if (!validPassword) return new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401, headers: corsHeaders });
        
        const token = await cryptoUtils.generateJWT({ id: user.id, name: user.name, email: user.email, role: user.role }, env.JWT_SECRET);
        return new Response(JSON.stringify({ token, user: { name: user.name, email: user.email, role: user.role } }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      } catch (err) {
        return new Response(JSON.stringify({ error: "Server login error", details: err.message }), { status: 500, headers: corsHeaders });
      }
    }

    // --- PROTECTED ROUTE BOUNDARY INTERCEPTOR ---
    if (url.pathname.startsWith("/api/")) {
      const user = await getAuthenticatedUser(request);
      if (!user) {
        return new Response(JSON.stringify({ error: "Unauthorized access token" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      
      // CRM Endpoint: Fetch All Customers
      if (url.pathname === "/api/customers" && request.method === "GET") {
        const { results } = await env.DB.prepare("SELECT * FROM customers ORDER BY created_at DESC").all();
        return new Response(JSON.stringify(results), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // CRM Endpoint: Create a Customer
      if (url.pathname === "/api/customers" && request.method === "POST") {
        const { name, phone, email, address, status, invoice_value } = await request.json();
        const id = crypto.randomUUID();
        await env.DB.prepare("INSERT INTO customers (id, name, phone, email, address, status, invoice_value) VALUES (?, ?, ?, ?, ?, ?, ?)")
          .bind(id, name, phone, email, address, status || 'Lead', invoice_value || 0.0).run();
        return new Response(JSON.stringify({ success: true, id }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // Time Tracker Endpoint: Clock In
      if (url.pathname === "/api/time/clockin" && request.method === "POST") {
        const { customer_id, notes } = await request.json();
        // Enforce safety constraint: Ensure worker is not already clocked in somewhere else
        const activeLog = await env.DB.prepare("SELECT id FROM time_logs WHERE user_id = ? AND clock_out IS NULL").bind(user.id).first();
        if (activeLog) return new Response(JSON.stringify({ error: "Active log detected. Clock out first." }), { status: 400, headers: corsHeaders });

        const id = crypto.randomUUID();
        await env.DB.prepare("INSERT INTO time_logs (id, user_id, customer_id, clock_in, notes) VALUES (?, ?, ?, datetime('now'), ?)")
          .bind(id, user.id, customer_id || null, notes || "").run();
        return new Response(JSON.stringify({ success: true, id }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // Time Tracker Endpoint: Clock Out
      if (url.pathname === "/api/time/clockout" && request.method === "POST") {
        const result = await env.DB.prepare("UPDATE time_logs SET clock_out = datetime('now') WHERE user_id = ? AND clock_out IS NULL").bind(user.id).run();
        if (result.changes === 0) return new Response(JSON.stringify({ error: "No active clock-in log found to close." }), { status: 404, headers: corsHeaders });
        return new Response(JSON.stringify({ success: true }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // Admin Data Fetch: View Complete Timesheet Ledger
      if (url.pathname === "/api/admin/timesheets" && request.method === "GET") {
        if (user.role !== 'admin') return new Response(JSON.stringify({ error: "Forbidden: Admin clearance required" }), { status: 403, headers: corsHeaders });
        const { results } = await env.DB.prepare(`
          SELECT tl.*, u.name as crew_name, c.name as customer_name 
          FROM time_logs tl 
          JOIN users u ON tl.user_id = u.id 
          LEFT JOIN customers c ON tl.customer_id = c.id 
          ORDER BY tl.clock_in DESC
        `).all();
        return new Response(JSON.stringify(results), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
    }

    // ==========================================
    // FRONTEND UI PORTAL DELIVERY (SPA)
    // ==========================================
    if (request.method === "GET" && !url.pathname.startsWith("/api/")) {
      const html = generateFrontendHTML();
      return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
    }

    return new Response(JSON.stringify({ error: "Endpoint Route Not Found" }), { status: 404, headers: corsHeaders });
  }
};

// ==========================================
// TECHGURU BRAND ASSETS
// ==========================================
const TECHGURU_LOGO_B64 = "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";

// ==========================================
// PREMIUM FRONTEND HTML GENERATOR
// ==========================================
function generateFrontendHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contractor Pro CRM Suite</title>
    <meta name="description" content="Professional contractor CRM suite with customer management, field time tracking, review dispatch, and admin panel.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <style>
      /* ================================================
         DESIGN SYSTEM — CSS CUSTOM PROPERTIES
         ================================================ */
      :root {
        /* Core palette — Deep dark with emerald accents */
        --bg-primary: #0a0e17;
        --bg-secondary: #111827;
        --bg-card: #151d2e;
        --bg-card-hover: #1a2438;
        --bg-input: #0d1220;
        --bg-overlay: rgba(0, 0, 0, 0.75);

        /* Borders & dividers */
        --border-subtle: rgba(255, 255, 255, 0.06);
        --border-default: rgba(255, 255, 255, 0.1);
        --border-hover: rgba(255, 255, 255, 0.15);
        --border-accent: rgba(52, 211, 153, 0.3);

        /* Text hierarchy */
        --text-primary: #f1f5f9;
        --text-secondary: #94a3b8;
        --text-tertiary: #64748b;
        --text-muted: #475569;

        /* Accent colors */
        --accent-emerald: #34d399;
        --accent-emerald-dim: #10b981;
        --accent-emerald-glow: rgba(52, 211, 153, 0.15);
        --accent-emerald-shadow: rgba(16, 185, 129, 0.25);
        --accent-blue: #60a5fa;
        --accent-blue-dim: #3b82f6;
        --accent-amber: #fbbf24;
        --accent-amber-dim: #f59e0b;
        --accent-rose: #fb7185;
        --accent-rose-dim: #f43f5e;
        --accent-violet: #a78bfa;

        /* Gradients */
        --gradient-hero: linear-gradient(135deg, #0a0e17 0%, #111827 50%, #0d1b2a 100%);
        --gradient-card: linear-gradient(145deg, #151d2e 0%, #111827 100%);
        --gradient-emerald: linear-gradient(135deg, #34d399 0%, #10b981 100%);
        --gradient-blue: linear-gradient(135deg, #60a5fa 0%, #3b82f6 100%);
        --gradient-rose: linear-gradient(135deg, #fb7185 0%, #f43f5e 100%);
        --gradient-glass: linear-gradient(135deg, rgba(255,255,255,0.03) 0%, rgba(255,255,255,0.01) 100%);

        /* Shadows */
        --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.3);
        --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.4);
        --shadow-lg: 0 8px 32px rgba(0, 0, 0, 0.5);
        --shadow-glow-emerald: 0 0 20px rgba(52, 211, 153, 0.15), 0 0 40px rgba(52, 211, 153, 0.05);
        --shadow-glow-blue: 0 0 20px rgba(96, 165, 250, 0.15);
        --shadow-glow-rose: 0 0 20px rgba(251, 113, 133, 0.15);

        /* Spacing */
        --radius-sm: 8px;
        --radius-md: 12px;
        --radius-lg: 16px;
        --radius-xl: 20px;
        --radius-full: 9999px;

        /* Transitions */
        --ease-smooth: cubic-bezier(0.4, 0, 0.2, 1);
        --duration-fast: 150ms;
        --duration-normal: 250ms;
        --duration-slow: 400ms;
      }

      /* ================================================
         RESET & BASE
         ================================================ */
      *, *::before, *::after {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }

      html {
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
        scroll-behavior: smooth;
      }

      body {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        background: var(--gradient-hero);
        color: var(--text-primary);
        min-height: 100vh;
        line-height: 1.6;
        overflow-x: hidden;
        display: flex;
        flex-direction: column;
      }

      /* Ambient background glow */
      body::before {
        content: '';
        position: fixed;
        top: -200px;
        right: -200px;
        width: 600px;
        height: 600px;
        background: radial-gradient(circle, rgba(52, 211, 153, 0.04) 0%, transparent 70%);
        pointer-events: none;
        z-index: 0;
      }

      body::after {
        content: '';
        position: fixed;
        bottom: -200px;
        left: -200px;
        width: 500px;
        height: 500px;
        background: radial-gradient(circle, rgba(96, 165, 250, 0.03) 0%, transparent 70%);
        pointer-events: none;
        z-index: 0;
      }

      /* ================================================
         SCROLLBAR
         ================================================ */
      ::-webkit-scrollbar { width: 6px; }
      ::-webkit-scrollbar-track { background: var(--bg-primary); }
      ::-webkit-scrollbar-thumb { background: var(--text-muted); border-radius: var(--radius-full); }
      ::-webkit-scrollbar-thumb:hover { background: var(--text-tertiary); }

      /* ================================================
         TYPOGRAPHY
         ================================================ */
      h1 {
        font-size: 1.75rem;
        font-weight: 800;
        letter-spacing: -0.03em;
        line-height: 1.2;
        color: var(--text-primary);
      }

      h2 {
        font-size: 1.35rem;
        font-weight: 700;
        letter-spacing: -0.02em;
        color: var(--text-primary);
      }

      h3 {
        font-size: 1.1rem;
        font-weight: 600;
        color: var(--text-primary);
      }

      .subtitle {
        font-size: 0.8rem;
        color: var(--text-tertiary);
        letter-spacing: 0.02em;
        margin-top: 2px;
      }

      .label {
        display: block;
        font-size: 0.68rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--text-tertiary);
        margin-bottom: 6px;
      }

      /* ================================================
         LAYOUT
         ================================================ */
      #app {
        position: relative;
        z-index: 1;
        width: 100%;
        max-width: 680px;
        margin: 0 auto;
        padding: 20px 16px 20px;
        flex: 1 0 auto;
        animation: fadeIn var(--duration-slow) var(--ease-smooth);
      }

      @keyframes fadeIn {
        from { opacity: 0; transform: translateY(8px); }
        to { opacity: 1; transform: translateY(0); }
      }

      @keyframes slideUp {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
      }

      @keyframes slideDown {
        from { opacity: 0; transform: translateY(-12px); }
        to { opacity: 1; transform: translateY(0); }
      }

      @keyframes scaleIn {
        from { opacity: 0; transform: scale(0.95); }
        to { opacity: 1; transform: scale(1); }
      }

      @keyframes pulse-glow {
        0%, 100% { box-shadow: 0 0 8px rgba(52, 211, 153, 0.2); }
        50% { box-shadow: 0 0 20px rgba(52, 211, 153, 0.4); }
      }

      @keyframes shimmer {
        0% { background-position: -200% center; }
        100% { background-position: 200% center; }
      }

      /* ================================================
         CARDS — Glassmorphism
         ================================================ */
      .card {
        background: var(--gradient-card);
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius-lg);
        padding: 20px;
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        transition: all var(--duration-normal) var(--ease-smooth);
        position: relative;
        overflow: hidden;
      }

      .card::before {
        content: '';
        position: absolute;
        inset: 0;
        background: var(--gradient-glass);
        pointer-events: none;
        border-radius: inherit;
      }

      .card:hover {
        border-color: var(--border-hover);
        transform: translateY(-1px);
        box-shadow: var(--shadow-md);
      }

      .card-elevated {
        box-shadow: var(--shadow-lg);
        border-color: var(--border-default);
      }

      .card-accent {
        border-color: var(--border-accent);
        box-shadow: var(--shadow-glow-emerald);
      }

      /* ================================================
         BUTTONS
         ================================================ */
      .btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        padding: 10px 20px;
        font-family: inherit;
        font-size: 0.85rem;
        font-weight: 600;
        border: none;
        border-radius: var(--radius-md);
        cursor: pointer;
        transition: all var(--duration-fast) var(--ease-smooth);
        position: relative;
        overflow: hidden;
        white-space: nowrap;
      }

      .btn::after {
        content: '';
        position: absolute;
        inset: 0;
        background: linear-gradient(rgba(255,255,255,0.1), transparent);
        opacity: 0;
        transition: opacity var(--duration-fast);
      }

      .btn:hover::after { opacity: 1; }
      .btn:active { transform: scale(0.97); }

      .btn-primary {
        background: var(--gradient-emerald);
        color: #022c22;
        box-shadow: 0 2px 8px var(--accent-emerald-shadow);
      }
      .btn-primary:hover {
        box-shadow: var(--shadow-glow-emerald);
        transform: translateY(-1px);
      }

      .btn-secondary {
        background: var(--bg-card);
        color: var(--text-secondary);
        border: 1px solid var(--border-default);
      }
      .btn-secondary:hover {
        background: var(--bg-card-hover);
        color: var(--text-primary);
        border-color: var(--border-hover);
      }

      .btn-blue {
        background: var(--gradient-blue);
        color: white;
        box-shadow: 0 2px 8px rgba(59, 130, 246, 0.25);
      }
      .btn-blue:hover { box-shadow: var(--shadow-glow-blue); }

      .btn-rose {
        background: var(--gradient-rose);
        color: white;
        box-shadow: 0 2px 8px rgba(244, 63, 94, 0.25);
      }
      .btn-rose:hover { box-shadow: var(--shadow-glow-rose); }

      .btn-ghost {
        background: transparent;
        color: var(--text-tertiary);
        padding: 8px 16px;
      }
      .btn-ghost:hover { color: var(--text-primary); background: rgba(255,255,255,0.04); }

      .btn-icon {
        width: 40px;
        height: 40px;
        padding: 0;
        border-radius: var(--radius-sm);
      }

      .btn-lg {
        padding: 14px 28px;
        font-size: 0.95rem;
        border-radius: var(--radius-lg);
      }

      .btn-block {
        width: 100%;
      }

      /* ================================================
         INPUTS & FORM CONTROLS
         ================================================ */
      .input {
        width: 100%;
        padding: 12px 16px;
        font-family: inherit;
        font-size: 0.9rem;
        color: var(--text-primary);
        background: var(--bg-input);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-md);
        outline: none;
        transition: all var(--duration-fast) var(--ease-smooth);
      }

      .input::placeholder {
        color: var(--text-muted);
      }

      .input:focus {
        border-color: var(--accent-emerald);
        box-shadow: 0 0 0 3px var(--accent-emerald-glow);
      }

      .input-group {
        margin-bottom: 16px;
      }

      select.input {
        appearance: none;
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2394a3b8' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
        background-repeat: no-repeat;
        background-position: right 14px center;
        padding-right: 40px;
        cursor: pointer;
      }

      /* ================================================
         BADGES & CHIPS
         ================================================ */
      .badge {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        font-size: 0.6rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        padding: 3px 10px;
        border-radius: var(--radius-full);
      }

      .badge-emerald { background: rgba(52, 211, 153, 0.12); color: var(--accent-emerald); }
      .badge-amber { background: rgba(251, 191, 36, 0.12); color: var(--accent-amber); }
      .badge-blue { background: rgba(96, 165, 250, 0.12); color: var(--accent-blue); }
      .badge-rose { background: rgba(251, 113, 133, 0.12); color: var(--accent-rose); }
      .badge-violet { background: rgba(167, 139, 250, 0.12); color: var(--accent-violet); }

      /* ================================================
         BOTTOM NAV
         ================================================ */
      #navbar {
        position: fixed;
        bottom: 0;
        left: 0;
        right: 0;
        display: flex;
        justify-content: space-around;
        align-items: center;
        padding: 8px 4px 12px;
        background: rgba(10, 14, 23, 0.85);
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        border-top: 1px solid var(--border-subtle);
        z-index: 100;
        transition: transform var(--duration-normal) var(--ease-smooth);
      }

      #navbar.hidden {
        transform: translateY(100%);
        pointer-events: none;
      }

      .nav-btn {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 3px;
        padding: 6px 12px;
        background: none;
        border: none;
        cursor: pointer;
        color: var(--text-muted);
        font-family: inherit;
        font-size: 0.62rem;
        font-weight: 500;
        letter-spacing: 0.02em;
        transition: all var(--duration-fast) var(--ease-smooth);
        border-radius: var(--radius-sm);
        position: relative;
      }

      .nav-btn i {
        font-size: 1.15rem;
        transition: transform var(--duration-fast) var(--ease-smooth);
      }

      .nav-btn:hover,
      .nav-btn.active {
        color: var(--accent-emerald);
      }

      .nav-btn:hover i,
      .nav-btn.active i {
        transform: translateY(-2px);
      }

      .nav-btn.active::after {
        content: '';
        position: absolute;
        top: -1px;
        left: 50%;
        transform: translateX(-50%);
        width: 20px;
        height: 2px;
        background: var(--accent-emerald);
        border-radius: var(--radius-full);
      }

      .nav-btn.nav-logout {
        color: var(--accent-rose);
      }
      .nav-btn.nav-logout:hover { color: var(--accent-rose-dim); }

      /* ================================================
         MODAL / OVERLAY
         ================================================ */
      .modal-overlay {
        position: fixed;
        inset: 0;
        background: var(--bg-overlay);
        backdrop-filter: blur(6px);
        -webkit-backdrop-filter: blur(6px);
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 20px;
        z-index: 200;
        animation: fadeIn var(--duration-fast) var(--ease-smooth);
      }

      .modal-overlay.hidden {
        display: none;
      }

      .modal-content {
        background: var(--bg-secondary);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-xl);
        padding: 28px;
        width: 100%;
        max-width: 440px;
        box-shadow: var(--shadow-lg);
        animation: scaleIn var(--duration-normal) var(--ease-smooth);
        position: relative;
      }

      .modal-content::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
        background: var(--gradient-emerald);
        border-radius: var(--radius-xl) var(--radius-xl) 0 0;
      }

      /* ================================================
         DATA TABLE
         ================================================ */
      .data-table-wrapper {
        background: var(--gradient-card);
        border-radius: var(--radius-lg);
        border: 1px solid var(--border-subtle);
        overflow: hidden;
      }

      .data-table {
        width: 100%;
        text-align: left;
        font-size: 0.82rem;
        border-collapse: collapse;
        white-space: nowrap;
      }

      .data-table thead {
        background: rgba(0, 0, 0, 0.2);
        border-bottom: 1px solid var(--border-subtle);
      }

      .data-table th {
        padding: 12px 16px;
        font-size: 0.65rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        color: var(--text-muted);
      }

      .data-table td {
        padding: 12px 16px;
        border-bottom: 1px solid var(--border-subtle);
        color: var(--text-secondary);
      }

      .data-table tbody tr {
        transition: background var(--duration-fast) var(--ease-smooth);
      }

      .data-table tbody tr:hover {
        background: rgba(255, 255, 255, 0.02);
      }

      .data-table tbody tr:last-child td {
        border-bottom: none;
      }

      /* ================================================
         STATUS DOT INDICATOR
         ================================================ */
      .status-dot {
        display: inline-block;
        width: 7px;
        height: 7px;
        border-radius: 50%;
        margin-right: 6px;
        vertical-align: middle;
      }

      .status-dot.active {
        background: var(--accent-emerald);
        box-shadow: 0 0 6px var(--accent-emerald);
        animation: pulse-glow 2s infinite;
      }

      /* ================================================
         PAGE HEADER
         ================================================ */
      .page-header {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        margin-bottom: 24px;
        animation: slideDown var(--duration-normal) var(--ease-smooth);
      }

      /* ================================================
         STAT CARDS
         ================================================ */
      .stat-bar {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
        gap: 12px;
        margin-bottom: 24px;
        animation: slideUp var(--duration-normal) var(--ease-smooth);
      }

      .stat-card {
        background: var(--gradient-card);
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius-md);
        padding: 14px 16px;
        text-align: center;
        position: relative;
        overflow: hidden;
      }

      .stat-card::before {
        content: '';
        position: absolute;
        inset: 0;
        background: var(--gradient-glass);
        pointer-events: none;
      }

      .stat-value {
        font-size: 1.5rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        margin-bottom: 2px;
      }

      .stat-label {
        font-size: 0.62rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        color: var(--text-muted);
      }

      /* ================================================
         CUSTOMER CARDS LIST
         ================================================ */
      .customer-list {
        display: flex;
        flex-direction: column;
        gap: 10px;
      }

      .customer-card {
        animation: slideUp var(--duration-normal) var(--ease-smooth);
        animation-fill-mode: both;
      }

      .customer-card:nth-child(1) { animation-delay: 0.05s; }
      .customer-card:nth-child(2) { animation-delay: 0.1s; }
      .customer-card:nth-child(3) { animation-delay: 0.15s; }
      .customer-card:nth-child(4) { animation-delay: 0.2s; }
      .customer-card:nth-child(5) { animation-delay: 0.25s; }
      .customer-card:nth-child(6) { animation-delay: 0.3s; }

      .customer-meta {
        display: flex;
        align-items: center;
        gap: 6px;
        margin-top: 6px;
        font-size: 0.75rem;
        color: var(--text-muted);
      }

      .customer-meta i {
        font-size: 0.65rem;
        color: var(--text-muted);
      }

      .customer-value {
        text-align: right;
      }

      .customer-value .amount {
        font-size: 0.95rem;
        font-weight: 700;
        color: var(--accent-emerald);
      }

      .customer-value .amount-label {
        font-size: 0.6rem;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.08em;
      }

      /* ================================================
         CLOCK PANEL
         ================================================ */
      .clock-panel {
        max-width: 420px;
        margin: 0 auto;
        animation: slideUp var(--duration-slow) var(--ease-smooth);
      }

      .clock-identity {
        text-align: center;
        padding: 20px 0;
        margin-bottom: 20px;
        border-bottom: 1px solid var(--border-subtle);
      }

      .clock-identity .avatar {
        width: 56px;
        height: 56px;
        border-radius: 50%;
        background: var(--gradient-emerald);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.3rem;
        font-weight: 800;
        color: #022c22;
        margin: 0 auto 10px;
        box-shadow: var(--shadow-glow-emerald);
      }

      .clock-buttons {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 12px;
        margin-top: 8px;
      }

      .clock-btn {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 6px;
        padding: 20px 16px;
        font-family: inherit;
        font-size: 0.9rem;
        font-weight: 700;
        border: none;
        border-radius: var(--radius-lg);
        cursor: pointer;
        transition: all var(--duration-fast) var(--ease-smooth);
      }

      .clock-btn i { font-size: 1.4rem; }

      .clock-btn:active { transform: scale(0.96); }

      .clock-btn.clock-in {
        background: var(--gradient-emerald);
        color: #022c22;
        box-shadow: 0 4px 16px var(--accent-emerald-shadow);
      }
      .clock-btn.clock-in:hover {
        box-shadow: var(--shadow-glow-emerald);
        transform: translateY(-2px);
      }

      .clock-btn.clock-out {
        background: var(--gradient-rose);
        color: white;
        box-shadow: 0 4px 16px rgba(244, 63, 94, 0.25);
      }
      .clock-btn.clock-out:hover {
        box-shadow: var(--shadow-glow-rose);
        transform: translateY(-2px);
      }

      /* ================================================
         REVIEW CARDS
         ================================================ */
      .review-card {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 12px;
      }

      .review-actions {
        display: flex;
        gap: 8px;
        flex-shrink: 0;
      }

      /* ================================================
         LOGIN SCREEN
         ================================================ */
      .login-wrapper {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        min-height: 68vh;
        animation: fadeIn var(--duration-slow) var(--ease-smooth);
      }

      .login-card {
        width: 100%;
        max-width: 380px;
      }

      .login-logo {
        text-align: center;
        margin-bottom: 32px;
      }

      .login-logo .logo-icon {
        width: 64px;
        height: 64px;
        border-radius: var(--radius-lg);
        background: var(--gradient-emerald);
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 0 auto 16px;
        font-size: 1.6rem;
        color: #022c22;
        box-shadow: var(--shadow-glow-emerald);
      }

      .login-logo h2 {
        font-size: 1.5rem;
        font-weight: 800;
        letter-spacing: -0.03em;
        background: linear-gradient(135deg, var(--text-primary) 0%, var(--accent-emerald) 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
      }

      .login-logo .login-subtitle {
        font-size: 0.78rem;
        color: var(--text-muted);
        margin-top: 4px;
      }

      .login-footer {
        text-align: center;
        margin-top: 20px;
        font-size: 0.72rem;
        color: var(--text-muted);
      }

      /* ================================================
         TOAST NOTIFICATIONS
         ================================================ */
      .toast {
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 14px 20px;
        border-radius: var(--radius-md);
        font-size: 0.82rem;
        font-weight: 500;
        z-index: 999;
        animation: slideDown var(--duration-normal) var(--ease-smooth), fadeOut var(--duration-normal) var(--ease-smooth) 2.5s forwards;
        box-shadow: var(--shadow-lg);
        max-width: 360px;
      }

      .toast-success {
        background: rgba(16, 185, 129, 0.95);
        color: #022c22;
        border: 1px solid rgba(52, 211, 153, 0.3);
      }

      .toast-error {
        background: rgba(244, 63, 94, 0.95);
        color: white;
        border: 1px solid rgba(251, 113, 133, 0.3);
      }

      .toast-info {
        background: rgba(59, 130, 246, 0.95);
        color: white;
        border: 1px solid rgba(96, 165, 250, 0.3);
      }

      @keyframes fadeOut {
        to { opacity: 0; transform: translateY(-10px); }
      }

      /* ================================================
         EMPTY STATE
         ================================================ */
      .empty-state {
        text-align: center;
        padding: 48px 20px;
        color: var(--text-muted);
      }

      .empty-state i {
        font-size: 2.5rem;
        margin-bottom: 12px;
        opacity: 0.4;
      }

      .empty-state p {
        font-size: 0.85rem;
      }

      /* ================================================
         LIVE CLOCK PULSE
         ================================================ */
      .pulse-live {
        color: var(--accent-amber);
        font-weight: 700;
        animation: pulse-glow 2s infinite;
      }

      /* ================================================
         RESPONSIVE
         ================================================ */
      @media (max-width: 480px) {
        h1 { font-size: 1.4rem; }
        .stat-bar { grid-template-columns: 1fr 1fr; }
        .data-table { font-size: 0.75rem; }
        .data-table th, .data-table td { padding: 10px 12px; }
        .review-card { flex-direction: column; align-items: flex-start; gap: 10px; }
        .review-actions { width: 100%; }
        .review-actions .btn { flex: 1; }
      }

      /* ================================================
         UTILITY CLASSES
         ================================================ */
      .hidden { display: none !important; }
      .flex { display: flex; }
      .items-center { align-items: center; }
      .justify-between { justify-content: space-between; }
      .gap-2 { gap: 8px; }
      .gap-3 { gap: 12px; }
      .mt-2 { margin-top: 8px; }
      .mt-4 { margin-top: 16px; }
      .mb-4 { margin-bottom: 16px; }
      .mb-6 { margin-bottom: 24px; }
      .text-emerald { color: var(--accent-emerald); }
      .text-amber { color: var(--accent-amber); }
      .text-rose { color: var(--accent-rose); }
      .text-blue { color: var(--accent-blue); }
      .text-muted { color: var(--text-muted); }
      .text-right { text-align: right; }
      .text-center { text-align: center; }
      .font-bold { font-weight: 700; }
      .overflow-x { overflow-x: auto; }

      /* ================================================
         GLOBAL FOOTER — POWERED BY TECHGURU
         Dark purple, blues, pinks & emerald green neon
         ================================================ */
      .app-global-footer {
        width: 100%;
        display: flex;
        justify-content: center;
        align-items: center;
        padding: 28px 16px 36px;
        margin-top: auto;
        position: relative;
        z-index: 10;
        transition: padding-bottom var(--duration-normal) var(--ease-smooth);
      }

      body.has-navbar .app-global-footer {
        padding-bottom: 96px; /* Clearance for fixed bottom navbar */
      }

      .techguru-footer-wrap {
        position: relative;
        display: inline-flex;
        align-items: center;
        justify-content: center;
      }

      /* Cyber Pill Capsule (No glow) */
      .techguru-brand-badge {
        position: relative;
        z-index: 1;
        display: inline-flex;
        align-items: center;
        gap: 13px;
        padding: 8px 22px 8px 12px;
        border-radius: var(--radius-full);
        background: linear-gradient(135deg, rgba(20, 8, 38, 0.95) 0%, rgba(13, 23, 44, 0.92) 50%, rgba(10, 14, 23, 0.96) 100%);
        border: 1px solid rgba(168, 85, 247, 0.35);
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.45),
                    inset 0 1px 1px rgba(255, 255, 255, 0.08);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        text-decoration: none;
        user-select: none;
        cursor: default;
        transition: all 0.35s var(--ease-smooth);
      }

      .techguru-brand-badge:hover {
        transform: translateY(-2px);
        border-color: rgba(0, 210, 255, 0.5);
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.55);
      }

      /* Logo Halo with Continuous Iridescent Gradient Spin (Clean, no glow) */
      .techguru-logo-halo {
        position: relative;
        display: flex;
        align-items: center;
        justify-content: center;
        width: 36px;
        height: 36px;
        border-radius: 50%;
        padding: 2px;
        background: linear-gradient(135deg, #00d2ff 0%, #7e22ce 33%, #ff007f 66%, #00ff87 100%);
        background-size: 250% 250%;
        animation: techguruHaloSpin 4.5s linear infinite;
        flex-shrink: 0;
      }

      @keyframes techguruHaloSpin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }

      .techguru-logo-img {
        width: 32px;
        height: 32px;
        border-radius: 50%;
        display: block;
        object-fit: cover;
        background: #090614;
        animation: techguruLogoCounterSpin 4.5s linear infinite;
      }

      @keyframes techguruLogoCounterSpin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(-360deg); }
      }

      /* Brand Typography */
      .techguru-content {
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        line-height: 1.15;
      }

      .techguru-subline {
        font-size: 0.62rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.22em;
        color: #94a3b8;
        opacity: 0.82;
        margin-bottom: 2px;
      }

      /* Animated TECHGURU text with flowing rainbow neon gradient (Crisp, no glow) */
      .techguru-title {
        font-size: 1.05rem;
        font-weight: 900;
        letter-spacing: 0.16em;
        text-transform: uppercase;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        background: linear-gradient(
          90deg, 
          #00d2ff 0%, 
          #3b82f6 18%, 
          #8b5cf6 36%, 
          #d946ef 52%, 
          #ff007f 68%, 
          #00ff87 84%, 
          #00d2ff 100%
        );
        background-size: 250% auto;
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        animation: techguruGradientShift 4.5s ease infinite;
      }

      @keyframes techguruGradientShift {
        0% { background-position: 0% center; }
        50% { background-position: 100% center; }
        100% { background-position: 0% center; }
      }

    </style>
</head>
<body>
    <!-- Main App Shell -->
    <div id="app"></div>

    <!-- Global App Footer -->
    <footer id="appGlobalFooter" class="app-global-footer">
        <div class="techguru-footer-wrap">
            <div class="techguru-brand-badge" title="Powered by TECHGURU">
                <div class="techguru-logo-halo">
                    <img src="data:image/webp;base64,${TECHGURU_LOGO_B64}" alt="TECHGURU Emblem" class="techguru-logo-img">
                </div>
                <div class="techguru-content">
                    <span class="techguru-subline">powered by</span>
                    <span class="techguru-title">TECHGURU</span>
                </div>
            </div>
        </div>
    </footer>

    <!-- Bottom Navigation Bar -->
    <nav id="navbar" class="hidden">
        <button id="navCrm" onclick="router.navigate('crm')" class="nav-btn">
            <i class="fa-solid fa-users"></i>
            <span>CRM</span>
        </button>
        <button id="navTracker" onclick="router.navigate('tracker')" class="nav-btn">
            <i class="fa-solid fa-clock"></i>
            <span>Tracker</span>
        </button>
        <button id="navReviews" onclick="router.navigate('reviews')" class="nav-btn">
            <i class="fa-solid fa-star"></i>
            <span>Reviews</span>
        </button>
        <button id="adminTabBtn" onclick="router.navigate('admin')" class="nav-btn hidden">
            <i class="fa-solid fa-shield-halved"></i>
            <span>Admin</span>
        </button>
        <button onclick="auth.logout()" class="nav-btn nav-logout">
            <i class="fa-solid fa-right-from-bracket"></i>
            <span>Logout</span>
        </button>
    </nav>

    <!-- Toast Container -->
    <div id="toastContainer"></div>

    <script>
        // ==========================================
        // SYSTEM STATE MANAGEMENT
        // ==========================================
        let token = localStorage.getItem('token') || '';
        let currentUser = JSON.parse(localStorage.getItem('user') || 'null');
        let customersData = [];
        let currentView = '';

        const API_URL = window.location.origin;

        // ==========================================
        // TOAST NOTIFICATION SYSTEM
        // ==========================================
        function showToast(message, type = 'success') {
            const container = document.getElementById('toastContainer');
            const toast = document.createElement('div');
            toast.className = 'toast toast-' + type;
            toast.innerHTML = '<i class="fa-solid ' + (type === 'success' ? 'fa-circle-check' : type === 'error' ? 'fa-circle-xmark' : 'fa-circle-info') + '" style="margin-right:8px"></i>' + message;
            container.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        }

        // ==========================================
        // AUTH ENGINE
        // ==========================================
        const auth = {
            async login(email, password) {
                try {
                    const res = await fetch(API_URL + '/api/auth/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email, password })
                    });
                    const data = await res.json();
                    if (data.error) throw new Error(data.error);
                    
                    token = data.token;
                    currentUser = data.user;
                    localStorage.setItem('token', token);
                    localStorage.setItem('user', JSON.stringify(currentUser));
                    
                    document.getElementById('navbar').classList.remove('hidden');
                    document.body.classList.add('has-navbar');
                    if (currentUser.role === 'admin') {
                        document.getElementById('adminTabBtn').classList.remove('hidden');
                    }
                    showToast('Welcome back, ' + currentUser.name + '!');
                    router.navigate('crm');
                } catch(e) {
                    showToast('Login Failed: ' + e.message, 'error');
                }
            },
            logout() {
                token = '';
                currentUser = null;
                localStorage.clear();
                document.getElementById('navbar').classList.add('hidden');
                document.body.classList.remove('has-navbar');
                document.getElementById('adminTabBtn').classList.add('hidden');
                router.navigate('login');
            }
        };

        // ==========================================
        // HELPER UTILITIES
        // ==========================================
        function getStatusBadgeClass(status) {
            switch(status) {
                case 'Complete': return 'badge-emerald';
                case 'In Progress': return 'badge-amber';
                case 'Quote': return 'badge-violet';
                default: return 'badge-blue';
            }
        }

        function getInitials(name) {
            return name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2);
        }

        function formatCurrency(value) {
            return '$' + parseFloat(value || 0).toLocaleString('en-US', { minimumFractionDigits: 0, maximumFractionDigits: 0 });
        }

        function updateNavActiveState(view) {
            document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
            const map = { crm: 'navCrm', tracker: 'navTracker', reviews: 'navReviews', admin: 'adminTabBtn' };
            if (map[view]) {
                const el = document.getElementById(map[view]);
                if (el) el.classList.add('active');
            }
        }

        // ==========================================
        // ROUTER & VIEW RENDERER
        // ==========================================
        const router = {
            async navigate(view) {
                const app = document.getElementById('app');
                if (!token && view !== 'login') view = 'login';
                currentView = view;
                updateNavActiveState(view);

                // ── LOGIN VIEW ──
                if (view === 'login') {
                    app.innerHTML = \`
                        <div class="login-wrapper">
                            <div class="login-card">
                                <div class="login-logo">
                                    <div class="logo-icon"><i class="fa-solid fa-hard-hat"></i></div>
                                    <h2>Contractor Pro Suite</h2>
                                    <p class="login-subtitle">CRM · Field Tracking · Reviews</p>
                                </div>
                                <div class="card card-elevated">
                                    <form id="loginForm" onsubmit="event.preventDefault(); auth.login(this.email.value, this.password.value)">
                                        <div class="input-group">
                                            <label class="label">Email Address</label>
                                            <input name="email" type="email" value="admin@contractor.local" required class="input" placeholder="you@company.com">
                                        </div>
                                        <div class="input-group">
                                            <label class="label">Password</label>
                                            <input name="password" type="password" value="Admin123!" required class="input" placeholder="••••••••">
                                        </div>
                                        <button type="submit" class="btn btn-primary btn-block btn-lg" style="margin-top:8px">
                                            <i class="fa-solid fa-arrow-right-to-bracket"></i> Secure Log In
                                        </button>
                                    </form>
                                </div>
                                <p class="login-footer"><i class="fa-solid fa-lock" style="margin-right:4px"></i> Demo credentials prefilled · Secured with PBKDF2-SHA256</p>
                            </div>
                        </div>
                    \`;
                    return;
                }

                // Hydrate customer data across views
                if (['crm', 'tracker', 'reviews'].includes(view)) {
                    try {
                        const res = await fetch(API_URL + '/api/customers', { headers: { 'Authorization': 'Bearer ' + token } });
                        if (res.status === 401) { auth.logout(); return; }
                        customersData = await res.json();
                    } catch(e) {
                        showToast('Failed to load customer data', 'error');
                        return;
                    }
                }

                // ── CRM VIEW ──
                if (view === 'crm') {
                    const totalValue = customersData.reduce((sum, c) => sum + parseFloat(c.invoice_value || 0), 0);
                    const statusCounts = { Lead: 0, Quote: 0, 'In Progress': 0, Complete: 0 };
                    customersData.forEach(c => { if (statusCounts[c.status] !== undefined) statusCounts[c.status]++; });

                    app.innerHTML = \`
                        <div class="page-header">
                            <div>
                                <h1>Customer Matrix</h1>
                                <p class="subtitle">\${customersData.length} total clients · Manage jobs & leads</p>
                            </div>
                            <button onclick="document.getElementById('crmModal').classList.remove('hidden')" class="btn btn-primary">
                                <i class="fa-solid fa-plus"></i> New Client
                            </button>
                        </div>

                        <div class="stat-bar">
                            <div class="stat-card">
                                <div class="stat-value text-emerald">\${formatCurrency(totalValue)}</div>
                                <div class="stat-label">Pipeline Value</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value text-blue">\${statusCounts.Lead}</div>
                                <div class="stat-label">New Leads</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value text-amber">\${statusCounts['In Progress']}</div>
                                <div class="stat-label">Active Jobs</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value" style="color: var(--accent-emerald)">\${statusCounts.Complete}</div>
                                <div class="stat-label">Completed</div>
                            </div>
                        </div>

                        <!-- Add Client Modal -->
                        <div id="crmModal" class="modal-overlay hidden">
                            <div class="modal-content">
                                <h3 style="margin-bottom:20px; font-size:1.15rem;">Add Customer Lead</h3>
                                <form onsubmit="event.preventDefault(); router.addCustomer(this)">
                                    <div class="input-group">
                                        <label class="label">Full Name or Business</label>
                                        <input type="text" name="cname" required class="input" placeholder="John's Roofing LLC">
                                    </div>
                                    <div class="input-group">
                                        <label class="label">Phone</label>
                                        <input type="text" name="cphone" class="input" placeholder="(555) 123-4567">
                                    </div>
                                    <div class="input-group">
                                        <label class="label">Email</label>
                                        <input type="email" name="cemail" class="input" placeholder="client@email.com">
                                    </div>
                                    <div class="input-group">
                                        <label class="label">Project Site Address</label>
                                        <input type="text" name="caddress" class="input" placeholder="123 Main St, City, ST">
                                    </div>
                                    <div class="input-group">
                                        <label class="label">Status</label>
                                        <select name="cstatus" class="input">
                                            <option>Lead</option><option>Quote</option><option>In Progress</option><option>Complete</option>
                                        </select>
                                    </div>
                                    <div class="input-group">
                                        <label class="label">Invoice / Contract Value ($)</label>
                                        <input type="number" step="0.01" name="cvalue" class="input" placeholder="0.00">
                                    </div>
                                    <div class="flex justify-between" style="margin-top:20px">
                                        <button type="button" onclick="document.getElementById('crmModal').classList.add('hidden')" class="btn btn-secondary">Cancel</button>
                                        <button type="submit" class="btn btn-primary"><i class="fa-solid fa-check"></i> Save Client</button>
                                    </div>
                                </form>
                            </div>
                        </div>

                        <!-- Customer Cards -->
                        <div class="customer-list">
                            \${customersData.length === 0 ? '<div class="empty-state"><i class="fa-solid fa-users"></i><p>No customers yet. Add your first client to get started.</p></div>' : ''}
                            \${customersData.map((c, i) => \`
                                <div class="card customer-card" style="animation-delay: \${i * 0.05}s">
                                    <div class="flex justify-between items-center">
                                        <div style="min-width:0; flex:1">
                                            <span class="badge \${getStatusBadgeClass(c.status)}">\${c.status}</span>
                                            <h3 style="margin-top:6px">\${c.name}</h3>
                                            <div class="customer-meta">
                                                <i class="fa-solid fa-location-dot"></i>
                                                <span>\${c.address || 'No location saved'}</span>
                                            </div>
                                            \${c.phone ? '<div class="customer-meta"><i class="fa-solid fa-phone"></i><span>' + c.phone + '</span></div>' : ''}
                                        </div>
                                        <div class="customer-value">
                                            <div class="amount">\${formatCurrency(c.invoice_value)}</div>
                                            <div class="amount-label">Contract</div>
                                        </div>
                                    </div>
                                </div>
                            \`).join('')}
                        </div>
                    \`;
                }

                // ── TIME TRACKER VIEW ──
                if (view === 'tracker') {
                    app.innerHTML = \`
                        <div class="page-header">
                            <div>
                                <h1>Field Time Tracker</h1>
                                <p class="subtitle">Clock in & out of job sites</p>
                            </div>
                        </div>

                        <div class="clock-panel">
                            <div class="card card-elevated card-accent">
                                <div class="clock-identity">
                                    <div class="avatar">\${getInitials(currentUser.name)}</div>
                                    <span class="label" style="margin-bottom:4px">Active Crew Identity</span>
                                    <h2>\${currentUser.name}</h2>
                                </div>

                                <form onsubmit="event.preventDefault();">
                                    <div class="input-group">
                                        <label class="label">Assign Job Site</label>
                                        <select id="trackJobSelect" class="input">
                                            <option value="">General Overhead / Shop Time</option>
                                            \${customersData.map(c => '<option value="' + c.id + '">' + c.name + '</option>').join('')}
                                        </select>
                                    </div>
                                    <div class="input-group">
                                        <label class="label">Shift Notes</label>
                                        <input id="trackNotes" type="text" class="input" placeholder="Framing, material run, cleanup...">
                                    </div>
                                    <div class="clock-buttons">
                                        <button onclick="router.clockIn()" type="button" class="clock-btn clock-in">
                                            <i class="fa-solid fa-play"></i>
                                            <span>Clock In</span>
                                        </button>
                                        <button onclick="router.clockOut()" type="button" class="clock-btn clock-out">
                                            <i class="fa-solid fa-stop"></i>
                                            <span>Clock Out</span>
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    \`;
                }

                // ── REVIEWS VIEW ──
                if (view === 'reviews') {
                    app.innerHTML = \`
                        <div class="page-header">
                            <div>
                                <h1>Review Dispatch</h1>
                                <p class="subtitle">Generate review traffic before leaving the site</p>
                            </div>
                        </div>

                        <div class="customer-list">
                            \${customersData.length === 0 ? '<div class="empty-state"><i class="fa-solid fa-star"></i><p>No clients available for review requests.</p></div>' : ''}
                            \${customersData.map((c, i) => \`
                                <div class="card customer-card review-card" style="animation-delay: \${i * 0.05}s">
                                    <div style="min-width:0; flex:1">
                                        <h3>\${c.name}</h3>
                                        <div class="customer-meta">
                                            <i class="fa-solid fa-phone"></i>
                                            <span>\${c.phone || 'No phone'}</span>
                                            <span style="margin:0 4px;color:var(--text-muted)">·</span>
                                            <i class="fa-solid fa-envelope"></i>
                                            <span>\${c.email || 'No email'}</span>
                                        </div>
                                    </div>
                                    <div class="review-actions">
                                        <button onclick="router.sendReview('\${c.phone}', '\${c.name}', 'sms')" class="btn btn-blue" title="Send SMS Review Request">
                                            <i class="fa-solid fa-comment-sms"></i> Text
                                        </button>
                                        <button onclick="router.sendReview('\${c.email}', '\${c.name}', 'email')" class="btn btn-primary" title="Send Email Review Request">
                                            <i class="fa-solid fa-envelope"></i> Email
                                        </button>
                                    </div>
                                </div>
                            \`).join('')}
                        </div>
                    \`;
                }

                // ── ADMIN VIEW ──
                if (view === 'admin') {
                    if (currentUser.role !== 'admin') { router.navigate('crm'); return; }
                    let logs = [];
                    try {
                        const res = await fetch(API_URL + '/api/admin/timesheets', { headers: { 'Authorization': 'Bearer ' + token } });
                        logs = await res.json();
                    } catch(e) {
                        showToast('Failed to load timesheet data', 'error');
                    }

                    app.innerHTML = \`
                        <div class="page-header">
                            <div>
                                <h1><i class="fa-solid fa-shield-halved" style="color:var(--accent-violet);margin-right:8px"></i>Admin Panel</h1>
                                <p class="subtitle">Complete labor hours audit trail</p>
                            </div>
                        </div>

                        <div class="stat-bar" style="grid-template-columns: 1fr 1fr;">
                            <div class="stat-card">
                                <div class="stat-value text-blue">\${logs.length}</div>
                                <div class="stat-label">Total Entries</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value text-amber">\${logs.filter(l => !l.clock_out).length}</div>
                                <div class="stat-label">Currently Clocked In</div>
                            </div>
                        </div>

                        <div class="overflow-x">
                            <div class="data-table-wrapper">
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>Crew</th>
                                            <th>Site</th>
                                            <th>Clock In</th>
                                            <th>Clock Out</th>
                                            <th>Notes</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        \${logs.length === 0 ? '<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--text-muted)">No timesheet entries recorded yet.</td></tr>' : ''}
                                        \${logs.map(l => \`
                                            <tr>
                                                <td style="font-weight:600;color:var(--text-primary)">\${l.crew_name}</td>
                                                <td style="color:var(--accent-emerald)">\${l.customer_name || 'General Overhead'}</td>
                                                <td style="font-size:0.75rem">\${new Date(l.clock_in).toLocaleString()}</td>
                                                <td style="font-size:0.75rem">\${l.clock_out ? new Date(l.clock_out).toLocaleString() : '<span class="pulse-live"><span class="status-dot active"></span>ON CLOCK</span>'}</td>
                                                <td style="font-size:0.75rem;font-style:italic;color:var(--text-tertiary)">\${l.notes || '—'}</td>
                                            </tr>
                                        \`).join('')}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    \`;
                }
            },

            async addCustomer(form) {
                const payload = {
                    name: form.cname.value,
                    phone: form.cphone.value,
                    email: form.cemail.value,
                    address: form.caddress.value,
                    status: form.cstatus.value,
                    invoice_value: parseFloat(form.cvalue.value) || 0
                };
                try {
                    await fetch(API_URL + '/api/customers', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                        body: JSON.stringify(payload)
                    });
                    document.getElementById('crmModal').classList.add('hidden');
                    showToast(payload.name + ' added successfully!');
                    router.navigate('crm');
                } catch(e) {
                    showToast('Failed to add customer', 'error');
                }
            },

            async clockIn() {
                const jobId = document.getElementById('trackJobSelect').value;
                const notes = document.getElementById('trackNotes').value;
                try {
                    const res = await fetch(API_URL + '/api/time/clockin', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                        body: JSON.stringify({ customer_id: jobId || null, notes })
                    });
                    const data = await res.json();
                    if (data.error) { showToast(data.error, 'error'); return; }
                    showToast('Successfully Clocked In! ⏱️');
                } catch(e) {
                    showToast('Clock in failed', 'error');
                }
            },

            async clockOut() {
                try {
                    const res = await fetch(API_URL + '/api/time/clockout', {
                        method: 'POST',
                        headers: { 'Authorization': 'Bearer ' + token }
                    });
                    const data = await res.json();
                    if (data.error) { showToast(data.error, 'error'); return; }
                    showToast('Successfully Clocked Out! ✅');
                } catch(e) {
                    showToast('Clock out failed', 'error');
                }
            },

            sendReview(target, name, type) {
                if (!target || target === 'undefined' || target === 'null' || target === '') {
                    showToast('No contact information available for this client.', 'info');
                    return;
                }
                const reviewUrl = "https://search.google.com/local/writereview?placeid=YOUR_GOOGLE_PLACE_ID";
                const msg = encodeURIComponent('Hi ' + name + ', thanks for working with us! If you are happy with our work, could you leave us a quick Google review here? ' + reviewUrl);
                
                if (type === 'sms') {
                    window.location.href = 'sms:' + target + '?body=' + msg;
                } else {
                    window.location.href = 'mailto:' + target + '?subject=Thank%20You!&body=' + msg;
                }
                showToast('Review request dispatched via ' + (type === 'sms' ? 'SMS' : 'Email') + '!');
            }
        };

        // ==========================================
        // APP INITIALIZATION
        // ==========================================
        if (token && currentUser) {
            document.getElementById('navbar').classList.remove('hidden');
            document.body.classList.add('has-navbar');
            if (currentUser.role === 'admin') {
                document.getElementById('adminTabBtn').classList.remove('hidden');
            }
            router.navigate('crm');
        } else {
            document.body.classList.remove('has-navbar');
            router.navigate('login');
        }
    </script>
</body>
</html>`;
}
