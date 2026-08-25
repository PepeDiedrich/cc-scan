-- Compatibility entry point. pipeline_runner.py uses sql/01_prefilter.sql directly.
-- Stage 1 deliberately performs no CVE classification.
SELECT 'Run pipeline_runner.py; SQL template moved to sql/01_prefilter.sql' AS notice;
