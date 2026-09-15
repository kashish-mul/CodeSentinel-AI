import { Finding } from '../../types';
import { FileInput } from './securityAnalyzer';

interface VulnerabilityDbEntry {
  ecosystem: 'npm' | 'pypi';
  package: string;
  vulnerableRange: (version: string) => boolean;
  fixedVersion: string;
  cve: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  title: string;
  description: string;
  recommendation: string;
}

// Compare semantic version e.g. "4.17.15" < "4.17.21"
function semverLessThan(v1: string, v2: string): boolean {
  const clean = (s: string) => s.replace(/[^0-9.]/g, '').split('.').map(n => parseInt(n, 10) || 0);
  const p1 = clean(v1);
  const p2 = clean(v2);

  for (let i = 0; i < Math.max(p1.length, p2.length); i++) {
    const num1 = p1[i] || 0;
    const num2 = p2[i] || 0;
    if (num1 < num2) return true;
    if (num1 > num2) return false;
  }
  return false;
}

const KNOWN_VULNERABILITIES: VulnerabilityDbEntry[] = [
  {
    ecosystem: 'npm',
    package: 'lodash',
    vulnerableRange: (v) => semverLessThan(v, '4.17.21'),
    fixedVersion: '4.17.21',
    cve: 'CVE-2021-23337',
    severity: 'HIGH',
    title: 'Prototype Pollution & Command Injection in lodash',
    description: 'Versions of lodash before 4.17.21 are vulnerable to Command Injection via template functionality and Prototype Pollution.',
    recommendation: 'Upgrade lodash to version 4.17.21 or later using `npm install lodash@^4.17.21`.'
  },
  {
    ecosystem: 'npm',
    package: 'axios',
    vulnerableRange: (v) => semverLessThan(v, '0.21.1'),
    fixedVersion: '0.21.1',
    cve: 'CVE-2020-28168',
    severity: 'MEDIUM',
    title: 'Server-Side Request Forgery (SSRF) in Axios',
    description: 'Axios versions prior to 0.21.1 improperly follow redirects leading to confidential data leakage across different domains.',
    recommendation: 'Upgrade axios to version 0.21.1 or later via `npm install axios@latest`.'
  },
  {
    ecosystem: 'npm',
    package: 'jsonwebtoken',
    vulnerableRange: (v) => semverLessThan(v, '9.0.0'),
    fixedVersion: '9.0.0',
    cve: 'CVE-2022-23529',
    severity: 'HIGH',
    title: 'Insecure Key Verification in jsonwebtoken',
    description: 'Versions of jsonwebtoken before 9.0.0 are vulnerable to arbitrary code execution if an attacker can manipulate secret/key objects.',
    recommendation: 'Upgrade jsonwebtoken to version 9.0.0 or later via `npm install jsonwebtoken@^9.0.0`.'
  },
  {
    ecosystem: 'npm',
    package: 'minimist',
    vulnerableRange: (v) => semverLessThan(v, '1.2.6'),
    fixedVersion: '1.2.6',
    cve: 'CVE-2021-44906',
    severity: 'CRITICAL',
    title: 'Prototype Pollution in minimist',
    description: 'Minimist prior to 1.2.6 allows prototype pollution through specially constructed command-line argument keys.',
    recommendation: 'Upgrade minimist to version 1.2.6 or later.'
  },
  {
    ecosystem: 'pypi',
    package: 'requests',
    vulnerableRange: (v) => semverLessThan(v, '2.31.0'),
    fixedVersion: '2.31.0',
    cve: 'CVE-2023-32681',
    severity: 'MEDIUM',
    title: 'Proxy-Authorization Header Leak in Requests',
    description: 'Requests prior to 2.31.0 inadvertently leaks Proxy-Authorization headers to destination servers when redirected.',
    recommendation: 'Upgrade requests via `pip install requests>=2.31.0`.'
  },
  {
    ecosystem: 'pypi',
    package: 'pillow',
    vulnerableRange: (v) => semverLessThan(v, '10.0.0'),
    fixedVersion: '10.0.0',
    cve: 'CVE-2023-44271',
    severity: 'HIGH',
    title: 'Denial of Service & Buffer Overflow in Pillow',
    description: 'Pillow versions before 10.0.0 suffer from uncontrolled resource consumption during text font rendering.',
    recommendation: 'Upgrade pillow via `pip install Pillow>=10.0.0`.'
  },
  {
    ecosystem: 'pypi',
    package: 'pyyaml',
    vulnerableRange: (v) => semverLessThan(v, '5.4.0'),
    fixedVersion: '5.4.0',
    cve: 'CVE-2020-14343',
    severity: 'CRITICAL',
    title: 'Arbitrary Code Execution in PyYAML',
    description: 'PyYAML versions prior to 5.4 allow arbitrary code execution through unsafe YAML loading.',
    recommendation: 'Upgrade PyYAML via `pip install pyyaml>=5.4` and switch to yaml.safe_load().'
  },
  {
    ecosystem: 'pypi',
    package: 'flask',
    vulnerableRange: (v) => semverLessThan(v, '2.2.5'),
    fixedVersion: '2.2.5',
    cve: 'CVE-2023-30861',
    severity: 'HIGH',
    title: 'Session Cookie Disclosure in Flask',
    description: 'Flask versions prior to 2.2.5 can leak secret keys or session cookies under specific caching configurations.',
    recommendation: 'Upgrade flask via `pip install flask>=2.2.5`.'
  }
];

export class DependencyScanner {
  public static scanFile(file: FileInput, scanId: string): Finding[] {
    const findings: Finding[] = [];
    const fileName = file.path.toLowerCase();

    // 1. Scan package.json
    if (fileName.endsWith('package.json')) {
      try {
        const pkg = JSON.parse(file.content);
        const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };

        for (const [name, rawVersion] of Object.entries(deps)) {
          const versionStr = String(rawVersion).replace(/[\^~>=<]/g, '').trim();
          const match = KNOWN_VULNERABILITIES.find(
            vuln => vuln.ecosystem === 'npm' && vuln.package.toLowerCase() === name.toLowerCase()
          );

          if (match && match.vulnerableRange(versionStr)) {
            findings.push({
              id: `sca-npm-${scanId}-${name}-${Math.random().toString(36).substr(2, 6)}`,
              scanId,
              category: 'SECURITY',
              severity: match.severity,
              title: `${match.title} (${name}@${versionStr})`,
              description: `Software Composition Analysis (SCA) detected vulnerable dependency '${name}' at version ${versionStr}. ${match.description}`,
              filePath: file.path,
              lineNumber: 1,
              codeSnippet: `"${name}": "${rawVersion}"`,
              recommendation: `${match.recommendation} (Target: >= ${match.fixedVersion})`,
              cwe: 'CWE-1395: Dependency on Vulnerable Third-Party Component',
              owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
              analysisMethod: 'SCA',
              dependencyInfo: {
                packageName: name,
                installedVersion: versionStr,
                fixedVersion: match.fixedVersion,
                cve: match.cve,
              }
            });
          }
        }
      } catch (err) {
        // invalid json
      }
    }

    // 2. Scan requirements.txt
    if (fileName.endsWith('requirements.txt')) {
      const lines = file.content.split('\n');
      lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) return;

        // Parse e.g. "requests==2.25.1" or "Pillow>=9.0.0,<10.0.0"
        const reqMatch = trimmed.match(/^([a-zA-Z0-9_\-]+)\s*(?:==|>=|<=|~=)\s*([0-9.]+)/);
        if (reqMatch) {
          const name = reqMatch[1].toLowerCase();
          const versionStr = reqMatch[2];

          const match = KNOWN_VULNERABILITIES.find(
            vuln => vuln.ecosystem === 'pypi' && vuln.package.toLowerCase() === name
          );

          if (match && match.vulnerableRange(versionStr)) {
            findings.push({
              id: `sca-pip-${scanId}-${name}-${idx + 1}-${Math.random().toString(36).substr(2, 6)}`,
              scanId,
              category: 'SECURITY',
              severity: match.severity,
              title: `${match.title} (${name}==${versionStr})`,
              description: `Software Composition Analysis (SCA) detected vulnerable PyPI dependency '${name}' version ${versionStr}. ${match.description}`,
              filePath: file.path,
              lineNumber: idx + 1,
              codeSnippet: trimmed,
              recommendation: `${match.recommendation} (Target: >= ${match.fixedVersion})`,
              cwe: 'CWE-1395: Dependency on Vulnerable Third-Party Component',
              owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
              analysisMethod: 'SCA',
              dependencyInfo: {
                packageName: name,
                installedVersion: versionStr,
                fixedVersion: match.fixedVersion,
                cve: match.cve,
              }
            });
          }
        }
      });
    }

    return findings;
  }
}
