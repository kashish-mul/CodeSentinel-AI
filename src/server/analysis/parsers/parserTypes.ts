import { Finding, Category, Severity } from '../../../types';

export interface AstNodeLocation {
  line: number;
  column: number;
  snippet: string;
}

export interface SecurityRuleContext {
  filePath: string;
  scanId: string;
  sourceContent: string;
  language: string;
}

export interface SecurityRule {
  id: string;
  name: string;
  category: Category;
  severity: Severity;
  cwe: string;
  owaspCategory: string;
  description: string;
  recommendation: string;
  check: (context: SecurityRuleContext) => Finding[];
}
