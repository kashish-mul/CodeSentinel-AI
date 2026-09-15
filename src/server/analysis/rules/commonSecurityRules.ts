import { Finding } from '../../../types';
import { SecurityRuleContext } from '../parsers/parserTypes';
import { XssRules } from './xssRules';
import { InjectionRules } from './injectionRules';
import { SsrfRules } from './ssrfRules';
import { CryptoRules } from './cryptoRules';
import { AuthRules } from './authRules';
import { SecretsRules } from './secretsRules';
import { FileRules } from './fileRules';

export class CommonSecurityRules {
  public static evaluateAll(ctx: SecurityRuleContext): Finding[] {
    const findings: Finding[] = [];
    
    findings.push(...XssRules.evaluate(ctx));
    findings.push(...InjectionRules.evaluate(ctx));
    findings.push(...SsrfRules.evaluate(ctx));
    findings.push(...CryptoRules.evaluate(ctx));
    findings.push(...AuthRules.evaluate(ctx));
    findings.push(...SecretsRules.evaluate(ctx));
    findings.push(...FileRules.evaluate(ctx));

    return findings;
  }
}
