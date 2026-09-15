import path from 'path';

export const SUPPORTED_EXTENSIONS = new Set([
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.mjs',
  '.cjs',
  '.py',
  '.java',
  '.sql',
  '.json',
  '.env',
  '.yml',
  '.yaml',
  '.go',
  '.php',
  '.rb',
  '.sh',
]);

export const IGNORED_DIRECTORIES = new Set([
  'node_modules',
  '.git',
  '.github',
  'dist',
  'build',
  'coverage',
  '.venv',
  'venv',
  'env',
  '__pycache__',
  '.next',
  '.nuxt',
  '.idea',
  '.vscode',
  'vendor',
  'target',
  'bin',
  'obj',
  'tmp',
  'temp',
]);

export const IGNORED_FILES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  '.DS_Store',
  'Thumbs.db',
]);

export function isPathSafe(filePath: string): boolean {
  if (!filePath || typeof filePath !== 'string') return false;
  const normalized = path.normalize(filePath).replace(/\\/g, '/');
  if (normalized.startsWith('../') || normalized.includes('/../') || normalized === '..') {
    return false;
  }
  if (path.isAbsolute(normalized)) {
    return false;
  }
  return true;
}

export function shouldAnalyzeFile(filePath: string): boolean {
  if (!filePath || !isPathSafe(filePath)) return false;
  const normalized = filePath.replace(/\\/g, '/');
  const segments = normalized.split('/');
  
  // Check if any directory segment is in the ignore set
  for (let i = 0; i < segments.length - 1; i++) {
    const dir = segments[i].toLowerCase();
    if (IGNORED_DIRECTORIES.has(dir) || dir.startsWith('.')) {
      return false;
    }
  }

  const fileName = segments[segments.length - 1];
  if (IGNORED_FILES.has(fileName)) return false;

  const ext = path.extname(fileName).toLowerCase();
  // Allow specific filenames like .env or requirements.txt
  if (fileName.startsWith('.env') || fileName === 'requirements.txt' || fileName === 'package.json') {
    return true;
  }

  return SUPPORTED_EXTENSIONS.has(ext);
}

export function detectLanguage(filePath: string): string {
  const fileName = path.basename(filePath).toLowerCase();
  const ext = path.extname(fileName).toLowerCase();

  if (fileName.startsWith('.env')) return 'env';
  if (fileName === 'package.json') return 'json';
  if (fileName === 'requirements.txt') return 'requirements';

  switch (ext) {
    case '.ts':
    case '.tsx':
      return 'typescript';
    case '.js':
    case '.jsx':
    case '.mjs':
    case '.cjs':
      return 'javascript';
    case '.py':
      return 'python';
    case '.java':
      return 'java';
    case '.sql':
      return 'sql';
    case '.json':
      return 'json';
    case '.yml':
    case '.yaml':
      return 'yaml';
    case '.go':
      return 'go';
    case '.php':
      return 'php';
    case '.rb':
      return 'ruby';
    case '.sh':
      return 'shell';
    default:
      return 'plaintext';
  }
}
