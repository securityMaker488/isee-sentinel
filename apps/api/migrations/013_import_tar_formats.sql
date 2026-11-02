ALTER TABLE import_runs DROP CONSTRAINT import_runs_format_check;
ALTER TABLE import_runs ADD CONSTRAINT import_runs_format_check CHECK(format IN ('zip','tar','tar.gz'));
