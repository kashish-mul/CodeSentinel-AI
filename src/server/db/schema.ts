export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(64) PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  name VARCHAR(255) NOT NULL,
  role VARCHAR(64) DEFAULT 'Security Engineer',
  password_hash TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS repositories (
  id VARCHAR(64) PRIMARY KEY,
  user_id VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  source VARCHAR(64) NOT NULL,
  url TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
  id VARCHAR(64) PRIMARY KEY,
  user_id VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
  repository_id VARCHAR(64),
  repository_name VARCHAR(255) NOT NULL,
  source_type VARCHAR(64) NOT NULL,
  source_url TEXT,
  status VARCHAR(32) NOT NULL,
  scores_json JSONB NOT NULL,
  severity_counts_json JSONB NOT NULL,
  total_files INT NOT NULL,
  total_lines INT NOT NULL,
  started_at TIMESTAMP WITH TIME ZONE NOT NULL,
  completed_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
  id VARCHAR(64) PRIMARY KEY,
  scan_id VARCHAR(64) REFERENCES scans(id) ON DELETE CASCADE,
  rule_id VARCHAR(64),
  title VARCHAR(255) NOT NULL,
  severity VARCHAR(32) NOT NULL,
  category VARCHAR(64) NOT NULL,
  cwe VARCHAR(64),
  owasp_category VARCHAR(128),
  file_path TEXT NOT NULL,
  line_number INT NOT NULL,
  code_snippet TEXT NOT NULL,
  recommendation TEXT NOT NULL,
  ast_node_type VARCHAR(64),
  analysis_method VARCHAR(32),
  dependency_info JSONB,
  ai_explanation JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS remediation_reports (
  id VARCHAR(64) PRIMARY KEY,
  scan_id VARCHAR(64) REFERENCES scans(id) ON DELETE CASCADE,
  user_id VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
  repository_name VARCHAR(255) NOT NULL,
  overall_score INT NOT NULL,
  executive_summary TEXT NOT NULL,
  findings_summary JSONB NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
`;
