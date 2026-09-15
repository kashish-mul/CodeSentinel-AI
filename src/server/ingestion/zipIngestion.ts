import JSZip from 'jszip';
import path from 'path';
import { SourceFile, RepositorySource } from '../../types';
import { shouldAnalyzeFile, detectLanguage, isPathSafe } from './fileFilters';

export class ZipIngestion {
  private static MAX_TOTAL_FILES = 80;
  private static MAX_FILE_SIZE = 500 * 1024; // 500 KB per file
  private static MAX_TOTAL_UNCOMPRESSED_BYTES = 10 * 1024 * 1024; // 10 MB limit (zip bomb defense)

  public static async ingestFromBase64(
    base64String: string,
    repositoryName: string = 'uploaded-archive.zip'
  ): Promise<RepositorySource> {
    return this.ingest(base64String, repositoryName);
  }

  public static async ingest(
    zipData: Buffer | Uint8Array | ArrayBuffer | string,
    repositoryName: string = 'uploaded-archive.zip'
  ): Promise<RepositorySource> {
    const zip = new JSZip();
    let loadedZip: JSZip;

    try {
      if (typeof zipData === 'string') {
        // Base64 or binary string
        const cleanBase64 = zipData.replace(/^data:application\/(zip|x-zip-compressed);base64,/, '');
        loadedZip = await zip.loadAsync(cleanBase64, { base64: true });
      } else {
        loadedZip = await zip.loadAsync(zipData);
      }
    } catch (err: any) {
      throw new Error(`Failed to decompress ZIP archive: ${err.message || 'Invalid ZIP format'}`);
    }

    const files: SourceFile[] = [];
    let totalUncompressedBytes = 0;

    // First detect root directory offset if all files are inside a single top-level folder
    const entries = Object.keys(loadedZip.files).filter(p => !loadedZip.files[p].dir);
    
    // Find common root folder prefix if present (e.g. "my-project-main/")
    let rootPrefix = '';
    if (entries.length > 0) {
      const firstSlash = entries[0].indexOf('/');
      if (firstSlash > 0) {
        const potentialRoot = entries[0].substring(0, firstSlash + 1);
        const allShareRoot = entries.every(e => e.startsWith(potentialRoot));
        if (allShareRoot) {
          rootPrefix = potentialRoot;
        }
      }
    }

    for (const rawPath of entries) {
      if (files.length >= this.MAX_TOTAL_FILES) {
        break;
      }

      const zipEntry = loadedZip.files[rawPath];
      if (zipEntry.dir) continue;

      // Strip root folder prefix for clean relative paths
      let relativePath = rawPath;
      if (rootPrefix && relativePath.startsWith(rootPrefix)) {
        relativePath = relativePath.slice(rootPrefix.length);
      }

      // Path traversal security check
      if (!isPathSafe(relativePath)) {
        console.warn(`[ZipIngestion] Skipped unsafe path: ${relativePath}`);
        continue;
      }

      // Check against ignored extensions and directories
      if (!shouldAnalyzeFile(relativePath)) {
        continue;
      }

      try {
        const content = await zipEntry.async('string');
        const size = Buffer.byteLength(content, 'utf8');

        if (size > this.MAX_FILE_SIZE) {
          console.warn(`[ZipIngestion] File ${relativePath} exceeds size limit (${size} bytes), skipping.`);
          continue;
        }

        totalUncompressedBytes += size;
        if (totalUncompressedBytes > this.MAX_TOTAL_UNCOMPRESSED_BYTES) {
          throw new Error('Total uncompressed content in ZIP exceeds safe safety limits (10MB limit).');
        }

        files.push({
          path: relativePath,
          content,
          language: detectLanguage(relativePath),
          size,
        });
      } catch (readErr: any) {
        console.warn(`[ZipIngestion] Could not read ${relativePath}:`, readErr);
      }
    }

    if (files.length === 0) {
      throw new Error('No supported source files (.js, .ts, .py, .java, .sql, .json) found in ZIP archive.');
    }

    const cleanName = path.basename(repositoryName, '.zip');

    return {
      name: cleanName,
      source: 'zip',
      files,
    };
  }
}
