-- PHOENIX Hunting Schema Alignment

ALTER TABLE hunting_queries
    ADD COLUMN query_text LONGTEXT NULL AFTER query_type;

ALTER TABLE hunting_queries
    ADD COLUMN severity VARCHAR(20) NOT NULL DEFAULT 'medium' AFTER query_text;

ALTER TABLE hunting_queries
    ADD COLUMN updated_at TIMESTAMP NULL AFTER created_at;

UPDATE hunting_queries
SET query_text = query_definition
WHERE query_text IS NULL
  AND query_definition IS NOT NULL;

UPDATE hunting_queries
SET updated_at = created_at
WHERE updated_at IS NULL;
