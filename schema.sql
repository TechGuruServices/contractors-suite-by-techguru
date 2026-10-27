-- Users & Crew Members Table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'crew', -- 'admin' or 'crew'
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Customers / CRM Leads Table
CREATE TABLE IF NOT EXISTS customers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT,
    email TEXT,
    address TEXT,
    status TEXT NOT NULL DEFAULT 'Lead', -- 'Lead', 'Quote', 'In Progress', 'Complete'
    invoice_value REAL DEFAULT 0.0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Crew Field Time Tracking Table
CREATE TABLE IF NOT EXISTS time_logs (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    customer_id TEXT,
    clock_in DATETIME DEFAULT CURRENT_TIMESTAMP,
    clock_out DATETIME,
    notes TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(customer_id) REFERENCES customers(id)
);

-- Insert Default Admin User for Initial Onboarding
-- Password plaintext: 'Admin123!' (Pre-hashed using PBKDF2-SHA256 with 100,000 iterations, hex representation)
-- NOTE: In production, use the sign-up endpoint to create genuine cryptographic hashes.
INSERT OR IGNORE INTO users (id, name, email, password_hash, role) 
VALUES (
    'admin-uuid-1111', 
    'Admin Contractor', 
    'admin@contractor.local', 
    'pbkdf2_sha256$100000$salt12345$8f91a54160358ef9c719811409bfd3976378e9f5e13d78c9df4efd6cd62660ad', 
    'admin'
);
