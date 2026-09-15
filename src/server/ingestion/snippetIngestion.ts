import { SourceFile, RepositorySource } from '../../types';
import { detectLanguage } from './fileFilters';

export class SnippetIngestion {
  public static ingest(
    codeSnippet: string,
    fileName: string = 'snippet.ts',
    customName: string = 'ad-hoc-snippet'
  ): RepositorySource {
    const trimmed = codeSnippet.trim();
    if (!trimmed) {
      throw new Error('Code snippet cannot be empty.');
    }

    const lang = detectLanguage(fileName);
    const sourceFile: SourceFile = {
      path: fileName,
      content: codeSnippet,
      language: lang,
      size: Buffer.byteLength(codeSnippet, 'utf8'),
    };

    return {
      name: customName,
      source: 'snippet',
      files: [sourceFile],
    };
  }
}
