-- Migration: Add 5-layer context configuration
-- Date: 2025-12-29
-- Description: Adds config, derived, and updated_at columns to contexts table
--              for the new 5-layer context model

-- Add config column (JSONB for 5-layer configuration)
ALTER TABLE contexts
ADD COLUMN IF NOT EXISTS config JSONB;

COMMENT ON COLUMN contexts.config IS '5-layer context configuration';

-- Add derived column (JSONB for cached derived requirements)
ALTER TABLE contexts
ADD COLUMN IF NOT EXISTS derived JSONB;

COMMENT ON COLUMN contexts.derived IS 'Cached derived requirements from algorithm resolver';

-- Add updated_at column
ALTER TABLE contexts
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE;

-- Increase algorithm column size for hybrid algorithm names
ALTER TABLE contexts
ALTER COLUMN algorithm TYPE VARCHAR(64);

-- Optional: Add index on sensitivity for filtering
CREATE INDEX IF NOT EXISTS idx_contexts_sensitivity
ON contexts ((config->'data_identity'->>'sensitivity'));

-- Optional: Add index on quantum_resistant for filtering
CREATE INDEX IF NOT EXISTS idx_contexts_quantum_resistant
ON contexts ((derived->>'quantum_resistant'));
