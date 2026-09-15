export class PatchService {
  public static generateUnifiedDiff(
    filePath: string,
    lineNumber: number,
    originalCode: string,
    remediatedCode: string
  ): string {
    const origLines = originalCode.split('\n');
    const newLines = remediatedCode.split('\n');

    const header = `--- a/${filePath}\n+++ b/${filePath}\n@@ -${lineNumber},${origLines.length} +${lineNumber},${newLines.length} @@`;
    const removed = origLines.map(l => `-${l}`).join('\n');
    const added = newLines.map(l => `+${l}`).join('\n');

    return `${header}\n${removed}\n${added}`;
  }
}
