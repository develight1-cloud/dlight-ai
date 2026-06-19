-- migrations/004_add_monthly_and_bonus.sql
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS monthly_credit_allowance INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS bonus_credits INTEGER DEFAULT 0;

-- Optional migration to move legacy `credits` into monthly_credit_allowance if desired:
-- UPDATE users SET monthly_credit_allowance = credits WHERE monthly_credit_allowance = 0 AND credits IS NOT NULL;
