CREATE SCHEMA IF NOT EXISTS hisn;

CREATE TABLE hisn.tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    api_key VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE hisn.watchlist (
    id SERIAL PRIMARY KEY,
    full_name_ar VARCHAR(500),
    full_name_en VARCHAR(500),
    list_type VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_watchlist_name_ar ON hisn.watchlist(full_name_ar);
CREATE INDEX idx_watchlist_name_en ON hisn.watchlist(full_name_en);
