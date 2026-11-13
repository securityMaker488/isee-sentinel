-- Cancelamento geral de jobs: estado terminal proprio e registro do pedido.
ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_status_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_status_check CHECK(status IN ('running','completed','failed','interrupted','cancelled'));
ALTER TABLE jobs ADD COLUMN cancel_requested_at timestamptz;
ALTER TABLE jobs ADD COLUMN cancel_requested_by uuid REFERENCES users(id) ON DELETE SET NULL;
