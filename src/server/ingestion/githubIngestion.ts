import { SourceFile, RepositorySource } from '../../types';
import { shouldAnalyzeFile, detectLanguage } from './fileFilters';

export class GitHubIngestion {
  private static parseRepoUrl(inputUrl: string): { owner: string; repo: string } {
    const cleaned = inputUrl.trim().replace(/\/$/, '');
    const match = cleaned.match(/github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)/);
    if (match) {
      return { owner: match[1], repo: match[2].replace(/\.git$/, '') };
    }
    const shortMatch = cleaned.match(/^([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)$/);
    if (shortMatch) {
      return { owner: shortMatch[1], repo: shortMatch[2].replace(/\.git$/, '') };
    }
    throw new Error('Invalid GitHub repository URL. Format must be https://github.com/owner/repo or owner/repo');
  }

  public static async ingest(githubUrl: string): Promise<RepositorySource> {
    const { owner, repo } = this.parseRepoUrl(githubUrl);
    const headers: Record<string, string> = {
      'User-Agent': 'CodeSentinel-AI-Static-Analyzer/2.0',
      'Accept': 'application/vnd.github.v3+json',
    };

    // 1. Get repository metadata to identify default branch
    const repoMetaRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
    
    if (repoMetaRes.status === 404) {
      throw new Error(`Repository "${owner}/${repo}" was not found or is private. For private code, upload as a ZIP archive.`);
    }
    if (repoMetaRes.status === 403) {
      const rateLimitReset = repoMetaRes.headers.get('x-ratelimit-reset');
      const resetMsg = rateLimitReset ? ` Rate limit resets in ${Math.ceil((Number(rateLimitReset) * 1000 - Date.now()) / 60000)}m.` : '';
      throw new Error(`GitHub API rate limit exceeded.${resetMsg} Please upload your repository as a ZIP archive.`);
    }
    if (!repoMetaRes.ok) {
      throw new Error(`GitHub API error (${repoMetaRes.status}): ${repoMetaRes.statusText}`);
    }

    const repoMeta = await repoMetaRes.json() as { default_branch?: string };
    const branch = repoMeta.default_branch || 'main';

    // 2. Fetch Git Tree recursively
    const treeRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`, { headers });
    if (!treeRes.ok) {
      // Fallback try 'master' branch if main failed
      if (branch === 'main') {
        const fallbackRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/master?recursive=1`, { headers });
        if (fallbackRes.ok) {
          return this.processTree(await fallbackRes.json(), owner, repo, 'master', githubUrl);
        }
      }
      throw new Error(`Could not fetch git tree for branch "${branch}" (${treeRes.status}).`);
    }

    const treeData = await treeRes.json();
    return this.processTree(treeData, owner, repo, branch, githubUrl);
  }

  private static async processTree(
    treeData: any,
    owner: string,
    repo: string,
    branch: string,
    originalUrl: string
  ): Promise<RepositorySource> {
    if (!treeData.tree || !Array.isArray(treeData.tree)) {
      throw new Error('Invalid repository tree response from GitHub.');
    }

    // Filter candidate files based on security/quality relevance
    const candidateEntries = treeData.tree.filter((item: any) => {
      return item.type === 'blob' && shouldAnalyzeFile(item.path);
    });

    if (candidateEntries.length === 0) {
      throw new Error(`No analyzable source files found in repository (${owner}/${repo}).`);
    }

    // Cap at 45 most relevant source files to respect rate limits and memory
    const filesToFetch = candidateEntries.slice(0, 45);
    const sourceFiles: SourceFile[] = [];

    // Concurrently fetch raw file contents in chunks
    const chunkSize = 8;
    for (let i = 0; i < filesToFetch.length; i += chunkSize) {
      const chunk = filesToFetch.slice(i, i + chunkSize);
      await Promise.all(
        chunk.map(async (entry: any) => {
          try {
            const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${entry.path}`;
            const res = await fetch(rawUrl);
            if (res.ok) {
              const content = await res.text();
              // Exclude files that are too large (e.g., minified bundles > 400KB)
              if (content.length <= 400000) {
                sourceFiles.push({
                  path: entry.path,
                  content,
                  language: detectLanguage(entry.path),
                  size: content.length,
                });
              }
            }
          } catch (fetchErr) {
            console.warn(`[GitHubIngestion] Failed to fetch ${entry.path}:`, fetchErr);
          }
        })
      );
    }

    if (sourceFiles.length === 0) {
      throw new Error(`Could not retrieve content for any files from ${owner}/${repo}.`);
    }

    return {
      name: `${owner}/${repo}`,
      source: 'github',
      files: sourceFiles,
      url: originalUrl,
    };
  }
}
