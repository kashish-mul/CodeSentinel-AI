import { FileInput } from './securityAnalyzer';

export interface GitHubRepoInfo {
  owner: string;
  repo: string;
  defaultBranch: string;
  stars: number;
  files: FileInput[];
}

export class GitHubScanner {
  public static parseRepoUrl(url: string): { owner: string; repo: string } {
    let clean = url.trim().replace(/\/+$/, '');
    clean = clean.replace(/\.git$/, '');

    const match = clean.match(/github\.com[/:]([a-zA-Z0-9_\-\.]+)\/([a-zA-Z0-9_\-\.]+)/i);
    if (!match) {
      throw new Error(`Invalid GitHub repository URL: "${url}". Format should be https://github.com/owner/repo`);
    }

    return {
      owner: match[1],
      repo: match[2]
    };
  }

  public static async fetchRepository(url: string, maxFiles: number = 60): Promise<GitHubRepoInfo> {
    const { owner, repo } = this.parseRepoUrl(url);

    const headers: Record<string, string> = {
      'User-Agent': 'CodeSentinel-AI-Security-Scanner/2.0',
      'Accept': 'application/vnd.github.v3+json',
    };

    // If a GITHUB_TOKEN is available in the environment, use it for higher rate limits
    if (process.env.GITHUB_TOKEN) {
      headers['Authorization'] = `token ${process.env.GITHUB_TOKEN}`;
    }

    // 1. Fetch Repository Metadata
    const repoApiUrl = `https://api.github.com/repos/${owner}/${repo}`;
    let repoRes: Response;
    try {
      repoRes = await fetch(repoApiUrl, { headers });
    } catch (networkErr: any) {
      throw new Error(`Network error connecting to GitHub: ${networkErr.message}`);
    }

    if (repoRes.status === 404) {
      throw new Error(`GitHub repository '${owner}/${repo}' was not found. Verify the URL and ensure the repository is public, or upload source files via the ZIP Archive option.`);
    }

    if (repoRes.status === 403) {
      const resetTime = repoRes.headers.get('x-ratelimit-reset');
      const waitMinutes = resetTime ? Math.max(1, Math.ceil((parseInt(resetTime, 10) * 1000 - Date.now()) / 60000)) : 15;
      throw new Error(`GitHub API rate limit reached for anonymous requests (resets in ~${waitMinutes} min). Please upload the repository as a ZIP archive or scan a preset demo.`);
    }

    if (!repoRes.ok) {
      throw new Error(`GitHub API returned error HTTP ${repoRes.status} for '${owner}/${repo}'`);
    }

    const repoData = await repoRes.json();
    const defaultBranch = repoData.default_branch || 'main';
    const stars = repoData.stargazers_count || 0;

    // 2. Fetch Recursive Git Tree
    const treeApiUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/${defaultBranch}?recursive=1`;
    const treeRes = await fetch(treeApiUrl, { headers });

    if (!treeRes.ok) {
      throw new Error(`Failed to fetch file tree for '${owner}/${repo}' on branch '${defaultBranch}' (HTTP ${treeRes.status}).`);
    }

    const treeData = await treeRes.json();
    if (!Array.isArray(treeData.tree)) {
      throw new Error(`GitHub file tree for '${owner}/${repo}' was empty or could not be read.`);
    }

    // Filter relevant source files
    const allowedExts = [
      '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
      '.py', '.java', '.go', '.sql', '.json',
      '.yaml', '.yml', '.env.example', 'package.json', 'requirements.txt'
    ];

    const excludedPaths = [
      'node_modules/', '.git/', 'dist/', 'build/', 'vendor/',
      '.next/', '.nuxt/', 'coverage/', '.min.js', '.min.css',
      'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'
    ];

    const candidateFiles = treeData.tree.filter((item: any) => {
      if (item.type !== 'blob' || !item.path) return false;
      const lower = item.path.toLowerCase();

      if (excludedPaths.some(ex => lower.includes(ex.toLowerCase()))) return false;

      return allowedExts.some(ext => lower.endsWith(ext) || lower === ext);
    });

    if (candidateFiles.length === 0) {
      throw new Error(`No analyzable source code files found in '${owner}/${repo}'. Supported formats: .js, .ts, .py, .java, .sql, .json, requirements.txt.`);
    }

    // Take top candidate files (limit to maxFiles to maintain high performance)
    const selectedFiles = candidateFiles.slice(0, maxFiles);
    const downloadedFiles: FileInput[] = [];

    // 3. Concurrently fetch raw file contents
    const fetchPromises = selectedFiles.map(async (fileItem: any) => {
      const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${defaultBranch}/${fileItem.path}`;
      try {
        const rawRes = await fetch(rawUrl);
        if (rawRes.ok) {
          const content = await rawRes.text();
          // Cap very large single files (> 1MB)
          if (content.length < 1_000_000) {
            downloadedFiles.push({
              path: fileItem.path,
              content
            });
          }
        }
      } catch (e) {
        // Continue downloading remaining files
      }
    });

    await Promise.all(fetchPromises);

    if (downloadedFiles.length === 0) {
      throw new Error(`Could not download source files from raw.githubusercontent.com for '${owner}/${repo}'. Repository may be private or files unavailable.`);
    }

    return {
      owner,
      repo,
      defaultBranch,
      stars,
      files: downloadedFiles
    };
  }
}
