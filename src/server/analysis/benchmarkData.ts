import { BenchmarkItem, BenchmarkResult } from '../../types';
import { SecurityAnalyzer } from './securityAnalyzer';

export const BENCHMARK_SAMPLES: BenchmarkItem[] = [
  {
    id: 'sample-1',
    name: 'Hard-coded AWS Secret Key',
    language: 'Python',
    code: `import boto3\n\nAWS_SECRET_KEY = "AKIA1234567890ABCDEF"\nclient = boto3.client('s3', aws_access_key_id=AWS_SECRET_KEY)`,
    isVulnerable: true,
    expectedCategory: 'SECURITY',
    expectedSeverity: 'CRITICAL',
    expectedVulnerabilityType: 'Exposed AWS Access Key ID'
  },
  {
    id: 'sample-2',
    name: 'Raw SQL Injection via String Concatenation',
    language: 'Python',
    code: `def get_user_profile(user_id):\n    query = "SELECT * FROM users WHERE id = " + user_id\n    return db.execute(query)`,
    isVulnerable: true,
    expectedCategory: 'SECURITY',
    expectedSeverity: 'HIGH',
    expectedVulnerabilityType: 'Potential SQL Injection Risk'
  },
  {
    id: 'sample-3',
    name: 'Arbitrary Dynamic Code Execution with eval()',
    language: 'JavaScript',
    code: `app.post('/compute', (req, res) => {\n  const result = eval(req.body.calculationExpr);\n  res.json({ result });\n});`,
    isVulnerable: true,
    expectedCategory: 'SECURITY',
    expectedSeverity: 'HIGH',
    expectedVulnerabilityType: 'Arbitrary Code Execution via eval()'
  },
  {
    id: 'sample-4',
    name: 'Weak Password Hashing with MD5',
    language: 'Python',
    code: `import hashlib\n\ndef hash_user_password(raw_password):\n    return hashlib.md5(raw_password.encode()).hexdigest()`,
    isVulnerable: true,
    expectedCategory: 'SECURITY',
    expectedSeverity: 'MEDIUM',
    expectedVulnerabilityType: 'Weak Cryptographic Hash Algorithm (MD5 / SHA-1)'
  },
  {
    id: 'sample-5',
    name: 'Safe Parameterized SQL Query with Prepared Statement',
    language: 'JavaScript',
    code: `async function findUserById(userId) {\n  const query = 'SELECT id, email, created_at FROM users WHERE id = $1';\n  return await db.query(query, [userId]);\n}`,
    isVulnerable: false,
    expectedCategory: 'SECURITY',
    expectedSeverity: 'INFO',
    expectedVulnerabilityType: 'None'
  },
  {
    id: 'sample-6',
    name: 'Secure Argon2 Password Hashing',
    language: 'Python',
    code: `import argon2\n\nph = argon2.PasswordHasher()\ndef securely_hash(password):\n    return ph.hash(password)`,
    isVulnerable: false,
    expectedCategory: 'SECURITY',
    expectedSeverity: 'INFO',
    expectedVulnerabilityType: 'None'
  },
  {
    id: 'sample-7',
    name: 'Command Injection via Interpolated Shell Execution',
    language: 'Python',
    code: `import os\n\ndef ping_host(host_input):\n    os.system("ping -c 1 " + host_input)`,
    isVulnerable: true,
    expectedCategory: 'SECURITY',
    expectedSeverity: 'CRITICAL',
    expectedVulnerabilityType: 'Potential Command Injection Risk'
  },
  {
    id: 'sample-8',
    name: 'Safe Shell Subprocess with Arguments Array',
    language: 'Python',
    code: `import subprocess\n\ndef safe_ping(host_input):\n    return subprocess.run(["ping", "-c", "1", host_input], capture_output=True, check=True)`,
    isVulnerable: false,
    expectedCategory: 'SECURITY',
    expectedSeverity: 'INFO',
    expectedVulnerabilityType: 'None'
  },
  {
    id: 'sample-9',
    name: 'Unsafe Deserialization via pickle.loads',
    language: 'Python',
    code: `import pickle\n\ndef process_payload(raw_bytes):\n    return pickle.loads(raw_bytes)`,
    isVulnerable: true,
    expectedCategory: 'SECURITY',
    expectedSeverity: 'HIGH',
    expectedVulnerabilityType: 'Potential Unsafe Deserialization'
  },
  {
    id: 'sample-10',
    name: 'Safe JSON Parsing with Strict Validation',
    language: 'JavaScript',
    code: `function parseIncomingPayload(jsonString) {\n  const parsed = JSON.parse(jsonString);\n  if (typeof parsed.id !== 'string') throw new Error('Invalid ID');\n  return parsed;\n}`,
    isVulnerable: false,
    expectedCategory: 'SECURITY',
    expectedSeverity: 'INFO',
    expectedVulnerabilityType: 'None'
  }
];

export function runBenchmarkEvaluation(): BenchmarkResult {
  let tp = 0; // True Positive: Vulnerable and detected
  let fp = 0; // False Positive: Safe but detected as vulnerable
  let tn = 0; // True Negative: Safe and not detected
  let fn = 0; // False Negative: Vulnerable but missed

  const detailedResults = BENCHMARK_SAMPLES.map((sample) => {
    const findings = SecurityAnalyzer.analyzeFile(
      { path: `benchmark/${sample.id}.${sample.language === 'Python' ? 'py' : 'js'}`, content: sample.code },
      'benchmark'
    );

    const hasSecurityFindings = findings.filter(f => f.category === 'SECURITY').length > 0;
    const groundTruth = sample.isVulnerable ? 'VULNERABLE' : 'SAFE';
    const predicted = hasSecurityFindings ? 'VULNERABLE' : 'SAFE';

    let status: 'CORRECT' | 'FALSE_POSITIVE' | 'FALSE_NEGATIVE';

    if (sample.isVulnerable && hasSecurityFindings) {
      tp++;
      status = 'CORRECT';
    } else if (!sample.isVulnerable && !hasSecurityFindings) {
      tn++;
      status = 'CORRECT';
    } else if (!sample.isVulnerable && hasSecurityFindings) {
      fp++;
      status = 'FALSE_POSITIVE';
    } else {
      fn++;
      status = 'FALSE_NEGATIVE';
    }

    return {
      id: sample.id,
      name: sample.name,
      language: sample.language,
      groundTruth: groundTruth as 'VULNERABLE' | 'SAFE',
      predicted: predicted as 'VULNERABLE' | 'SAFE',
      status,
      detectedVulnerabilities: findings.map(f => f.title),
      snippet: sample.code,
    };
  });

  const totalSamples = BENCHMARK_SAMPLES.length;
  const vulnerableSamples = BENCHMARK_SAMPLES.filter(s => s.isVulnerable).length;
  const safeSamples = totalSamples - vulnerableSamples;

  const precision = (tp + fp) > 0 ? tp / (tp + fp) : 0;
  const recall = (tp + fn) > 0 ? tp / (tp + fn) : 0;
  const f1Score = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const accuracy = (tp + tn) / totalSamples;

  return {
    totalSamples,
    vulnerableSamples,
    safeSamples,
    truePositives: tp,
    falsePositives: fp,
    trueNegatives: tn,
    falseNegatives: fn,
    precision: Number(precision.toFixed(3)),
    recall: Number(recall.toFixed(3)),
    f1Score: Number(f1Score.toFixed(3)),
    accuracy: Number(accuracy.toFixed(3)),
    detailedResults,
  };
}
