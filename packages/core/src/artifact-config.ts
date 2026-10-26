import type { ArtifactAnalysisReport } from './artifact-types.js';
import { ArtifactAnalysisError } from './artifact-types.js';
import { addFinding, boolean, fact, isoDate, list, objectEntries, record, strings, text, type JsonObject } from './artifact-support.js';

export function analyzeDependencies(root: JsonObject, report: ArtifactAnalysisReport): void {
  if (root.bomFormat === 'CycloneDX') {
    if (!['1.4', '1.5', '1.6'].includes(String(root.specVersion))) throw new ArtifactAnalysisError('CycloneDX suportado: 1.4 a 1.6 em JSON.');
    report.format = `cyclonedx-${root.specVersion}`;
    const components = list(root.components, 'components');
    let withHashes = 0;
    components.forEach((raw, index) => {
      const component = record(raw, 'componente');
      text(component.name, 'Nome de componente', 512);
      text(component.type, 'Tipo de componente', 80);
      const location = `/components/${index}`;
      if (component.version !== undefined) text(component.version, 'Versão', 200);
      if (!component.version) addFinding(report, { ruleId: 'DEP-VERSION-001', severity: 'low', title: 'Componente sem versão no inventário', location, recommendation: 'Registre a versão instalada para permitir correlação reproduzível com avisos de segurança.' }, component);
      const hashes = component.hashes === undefined ? [] : list(component.hashes, 'hashes');
      const strong = hashes.some(rawHash => {
        const hash = record(rawHash, 'hash');
        const alg = text(hash.alg, 'Algoritmo', 40);
        const content = text(hash.content, 'Digest', 256);
        return (alg === 'SHA-256' && /^[a-fA-F0-9]{64}$/.test(content)) || (alg === 'SHA-512' && /^[a-fA-F0-9]{128}$/.test(content));
      });
      if (strong) withHashes++;
      else addFinding(report, { ruleId: 'DEP-BOM-HASH-001', severity: 'info', title: 'SBOM sem hash SHA-256/SHA-512 do componente', location, recommendation: 'Complete a proveniência com hashes dos artefatos distribuídos quando aplicável.' }, component);
    });
    fact(report, 'Componentes', components.length);
    fact(report, 'Componentes com hash forte declarado', withHashes);
  } else {
    if (root.lockfileVersion !== 2 && root.lockfileVersion !== 3) throw new ArtifactAnalysisError('Envie package-lock.json v2/v3 ou CycloneDX JSON 1.4–1.6.');
    report.format = `npm-lock-v${root.lockfileVersion}`;
    const packages = objectEntries(root.packages, 'packages').filter(([name]) => name !== '');
    let installScripts = 0;
    let localLinks = 0;
    packages.forEach(([name, raw], index) => {
      const pkg = record(raw, 'pacote');
      const location = `/packages/#${index + 1}`;
      text(name, 'Chave do pacote', 1024);
      if (pkg.link === true) { localLinks++; return; }
      if (pkg.link !== undefined && typeof pkg.link !== 'boolean') throw new ArtifactAnalysisError('link deve ser booleano.');
      if (pkg.hasInstallScript !== undefined && typeof pkg.hasInstallScript !== 'boolean') throw new ArtifactAnalysisError('hasInstallScript deve ser booleano.');
      if (pkg.hasInstallScript === true) {
        installScripts++;
        addFinding(report, { ruleId: 'DEP-INSTALL-001', severity: 'info', title: 'Dependência declara script de instalação', location, recommendation: 'Revise a procedência e a necessidade do script antes de permitir sua execução. A presença do script não indica malware.' }, pkg);
      }
      const resolved = pkg.resolved === undefined ? '' : text(pkg.resolved, 'resolved', 8192);
      if (/^http:\/\//i.test(resolved)) addFinding(report, { ruleId: 'DEP-TRANSPORT-001', severity: 'high', title: 'Dependência resolvida por HTTP sem TLS', location, recommendation: 'Use origem HTTPS confiável e regenere o lockfile em ambiente controlado.' }, pkg);
      const sri = pkg.integrity === undefined ? '' : text(pkg.integrity, 'integrity', 1024);
      if (/^https?:\/\//i.test(resolved) && !sri.split(/\s+/).some(token => /^sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}$/.test(token))) {
        addFinding(report, { ruleId: 'DEP-INTEGRITY-001', severity: 'medium', title: 'Artefato remoto sem integridade SHA-256/384/512 declarada', location, recommendation: 'Reconstrua o lockfile com integridade forte e preserve a origem; o hash declarado ainda exige validação no download.' }, pkg);
      }
      if (/^(?:git(?:\+[^:]+)?:|github:|git@)/i.test(resolved) && !/#[a-fA-F0-9]{40}$/.test(resolved)) addFinding(report, { ruleId: 'DEP-GIT-001', severity: 'medium', title: 'Dependência Git sem commit completo fixado', location, recommendation: 'Fixe um commit revisado e registre sua proveniência.' }, pkg);
    });
    fact(report, 'Dependências', packages.length);
    fact(report, 'Links locais não resolvidos', localLinks);
    fact(report, 'Scripts de instalação declarados', installScripts);
  }
  report.limitations.push('Inventário e higiene do artefato enviado. Não consulta CVEs, não resolve versões, não baixa pacotes, não verifica assinaturas e não confirma a instalação real.');
}

function analyzeIamPolicy(policy: JsonObject, location: string, report: ArtifactAnalysisReport): number {
  const statements = Array.isArray(policy.Statement) ? list(policy.Statement, 'Statement') : [record(policy.Statement, 'Statement')];
  statements.forEach((raw, index) => {
    const statement = record(raw, 'Statement');
    const at = `${location}/Statement/${index}`;
    if (statement.Effect !== 'Allow' && statement.Effect !== 'Deny') throw new ArtifactAnalysisError('Statement.Effect deve ser Allow ou Deny.');
    if ((statement.Action !== undefined) === (statement.NotAction !== undefined)) throw new ArtifactAnalysisError('Statement exige exatamente Action ou NotAction.');
    const implicitTrustResource = statement.Principal !== undefined && statement.Resource === undefined && statement.NotResource === undefined;
    if (!implicitTrustResource && (statement.Resource !== undefined) === (statement.NotResource !== undefined)) throw new ArtifactAnalysisError('Statement exige Resource/NotResource ou Principal para política de confiança.');
    const actions = strings(statement.Action ?? statement.NotAction, 'Action/NotAction');
    const resources = implicitTrustResource ? [] : strings(statement.Resource ?? statement.NotResource, 'Resource/NotResource');
    const conditional = statement.Condition !== undefined && Object.keys(record(statement.Condition, 'Condition')).length > 0;
    if (statement.Effect !== 'Allow') return;
    if (statement.NotAction !== undefined || statement.NotResource !== undefined) addFinding(report, { ruleId: 'IAM-NEGATED-001', severity: 'medium', title: 'Permissão Allow usa complemento de ações ou recursos', location: at, recommendation: 'Revise o conjunto concedido por NotAction/NotResource e prefira permissões específicas quando possível.', confidence: 'medium' }, statement);
    if (statement.Action !== undefined && actions.includes('*') && statement.Resource !== undefined && resources.includes('*')) addFinding(report, { ruleId: 'IAM-ADMIN-001', severity: conditional ? 'medium' : 'high', title: conditional ? 'Declaração de acesso amplo condicionada' : 'Declaração permite todas as ações em todos os recursos', location: at, recommendation: 'Substitua os curingas por ações e recursos necessários e valide políticas efetivas, limites e negações.', confidence: 'medium' }, statement);
    let principals: string[] = [];
    if (statement.Principal !== undefined) {
      principals = typeof statement.Principal === 'string' ? [statement.Principal] : Object.values(record(statement.Principal, 'Principal')).flatMap(item => strings(item, 'Principal'));
    }
    if (principals.includes('*')) addFinding(report, { ruleId: 'IAM-PUBLIC-001', severity: conditional ? 'medium' : 'high', title: conditional ? 'Principal curinga depende de condições a revisar' : 'Declaração Allow com principal público', location: at, recommendation: 'Restrinja os principais autorizados e confirme o efeito de Conditions, Deny e controles do serviço.', confidence: 'medium' }, statement);
  });
  return statements.length;
}

export function analyzeCloud(root: JsonObject, report: ArtifactAnalysisReport): void {
  report.format = root.format === 'sentinel.cloud.v1' ? 'sentinel.cloud.v1' : root.Statement ? 'aws-iam-policy' : 'aws-s3-public-access-block';
  let statements = 0;
  let buckets = 0;
  let recognized = false;
  if (root.Statement !== undefined) { recognized = true; statements += analyzeIamPolicy(root, '', report); }
  if (root.format === 'sentinel.cloud.v1') {
    recognized = true;
    list(root.policies ?? [], 'policies').forEach((item, index) => { statements += analyzeIamPolicy(record(item), `/policies/${index}`, report); });
  }
  const checkBlock = (value: unknown, location: string): void => {
    const config = record(value, 'PublicAccessBlockConfiguration');
    for (const key of ['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets']) {
      const active = boolean(config[key], key);
      if (!active) addFinding(report, { ruleId: 'CLOUD-S3-BLOCK-001', severity: 'medium', title: 'Controle de bloqueio de acesso público S3 desabilitado no export', location: `${location}/${key}`, recommendation: 'Verifique a necessidade de exposição e habilite o bloqueio no nível apropriado. O valor isolado não demonstra que o bucket está público.' }, { control: key, enabled: active });
    }
    buckets++;
  };
  if (root.PublicAccessBlockConfiguration !== undefined) { recognized = true; checkBlock(root.PublicAccessBlockConfiguration, '/PublicAccessBlockConfiguration'); }
  if (root.format === 'sentinel.cloud.v1') list(root.buckets ?? [], 'buckets').forEach((item, index) => checkBlock(record(item).PublicAccessBlockConfiguration, `/buckets/${index}/PublicAccessBlockConfiguration`));
  if (!recognized) throw new ArtifactAnalysisError('Envie política IAM, PublicAccessBlockConfiguration S3 ou sentinel.cloud.v1.');
  fact(report, 'Declarações IAM analisadas', statements);
  fact(report, 'Configurações S3 analisadas', buckets);
  report.limitations.push('Revisão estática de declarações exportadas. Não calcula permissões efetivas, não consulta a nuvem e não considera políticas externas, SCPs, permissions boundaries, estado atual ou todos os operadores Condition.');
}

export function analyzeIdentities(root: JsonObject, report: ArtifactAnalysisReport): void {
  if (root.format !== 'sentinel.identity.v1') throw new ArtifactAnalysisError('Formato esperado: sentinel.identity.v1.');
  report.format = 'sentinel.identity.v1';
  const observed = new Date(isoDate(root.observedAt)).getTime();
  const accounts = list(root.accounts, 'accounts');
  const seen = new Set<string>();
  let enabled = 0;
  let privileged = 0;
  accounts.forEach((item, index) => {
    const account = record(item, 'conta');
    const id = text(account.id, 'ID de conta', 256);
    if (!id || seen.has(id)) throw new ArtifactAnalysisError('IDs de conta vazios ou duplicados.');
    seen.add(id);
    const active = boolean(account.enabled, 'enabled');
    const admin = boolean(account.privileged, 'privileged');
    const mfa = boolean(account.mfaEnabled, 'mfaEnabled');
    const location = `/accounts/${index}`;
    if (active) enabled++;
    if (active && admin) privileged++;
    if (active && !mfa) addFinding(report, { ruleId: 'IDENTITY-MFA-001', severity: admin ? 'high' : 'medium', title: admin ? 'Conta privilegiada ativa sem MFA declarada' : 'Conta ativa sem MFA declarada', location, recommendation: 'Confirme o tipo de conta e imponha autenticação forte adequada. Contas de serviço exigem controles próprios.' }, account);
    if (account.lastLoginAt !== undefined && account.lastLoginAt !== null) {
      const last = new Date(isoDate(account.lastLoginAt)).getTime();
      if (last > observed) throw new ArtifactAnalysisError('lastLoginAt posterior ao instante observado.');
      if (active && observed - last > 90 * 86400000) addFinding(report, { ruleId: 'IDENTITY-DORMANT-001', severity: admin ? 'medium' : 'low', title: 'Conta ativa sem login há mais de 90 dias no export', location, recommendation: 'Verifique a necessidade da conta e desabilite-a somente após confirmar dependências e responsável.' }, account);
    }
  });
  fact(report, 'Contas exportadas', accounts.length); fact(report, 'Contas ativas', enabled); fact(report, 'Contas privilegiadas ativas', privileged);
  fact(report, 'Instante declarado da coleta', new Date(observed).toISOString());
  report.limitations.push('Depende da exatidão dos campos exportados. Não autentica usuários, não coleta senhas, não altera diretórios e não infere que MFA declarada seja resistente a phishing.');
}

export function analyzeAi(root: JsonObject, report: ArtifactAnalysisReport): void {
  if (root.format !== 'sentinel.ai.v1') throw new ArtifactAnalysisError('Formato esperado: sentinel.ai.v1.');
  report.format = 'sentinel.ai.v1';
  const tools = list(root.tools, 'tools');
  tools.forEach((item, index) => {
    const tool = record(item, 'ferramenta');
    text(tool.name, 'Nome da ferramenta', 256);
    const active = boolean(tool.enabled, 'enabled');
    const approval = boolean(tool.requiresApproval, 'requiresApproval');
    const capabilities = list(tool.capabilities, 'capabilities', 4).map(item => text(item, 'capacidade', 30));
    if (capabilities.some(item => !['read', 'write', 'execute', 'network'].includes(item)) || new Set(capabilities).size !== capabilities.length) throw new ArtifactAnalysisError('Capacidades suportadas: read, write, execute, network, sem duplicatas.');
    const hosts = tool.allowedHosts === undefined ? undefined : list(tool.allowedHosts, 'allowedHosts').map(item => text(item, 'host', 256));
    if (active && !approval && capabilities.some(item => item === 'execute' || item === 'write')) addFinding(report, { ruleId: 'AI-ACTION-001', severity: capabilities.includes('execute') ? 'high' : 'medium', title: 'Ferramenta de IA permite ação com efeito sem aprovação', location: `/tools/${index}`, recommendation: 'Restrinja capacidades, aplique autorização fora do modelo e exija aprovação para ações sensíveis. Valide as barreiras no executor.' }, tool);
    if (active && capabilities.includes('network') && (!hosts || hosts.includes('*'))) addFinding(report, { ruleId: 'AI-EGRESS-001', severity: 'medium', title: 'Ferramenta de IA sem destino de rede restrito no export', location: `/tools/${index}`, recommendation: 'Defina destinos permitidos e verifique redirecionamentos, resolução DNS e bloqueio de endereços internos no executor.' }, tool);
  });
  if (root.dataRetention !== undefined) {
    const retention = record(root.dataRetention, 'dataRetention');
    const stores = boolean(retention.storesPrompts, 'storesPrompts');
    const redacts = boolean(retention.redactionEnabled, 'redactionEnabled');
    if (stores && !redacts) addFinding(report, { ruleId: 'AI-RETENTION-001', severity: 'medium', title: 'Registro de prompts sem redação de dados declarada', location: '/dataRetention', recommendation: 'Minimize o conteúdo retido, remova segredos e configure acesso e prazo de retenção.' }, retention);
  }
  if (root.credentials !== undefined) {
    objectEntries(root.credentials, 'credentials').forEach(([, value], index) => {
      const credential = text(value, 'Referência de credencial', 8192);
      if (credential && !/^(?:env:[A-Z_][A-Z0-9_]*|secret-ref:[A-Za-z0-9_./-]+|\$\{[A-Z_][A-Z0-9_]*\})$/.test(credential)) addFinding(report, { ruleId: 'AI-CREDENTIAL-001', severity: 'high', title: 'Valor de credencial literal no artefato de IA', location: `/credentials/#${index}`, recommendation: 'Use referência a armazenamento de segredos e rotacione valores expostos. O valor não é incluído no relatório.', confidence: 'medium' }, credential);
    });
  }
  fact(report, 'Ferramentas declaradas', tools.length);
  report.limitations.push('Revisão de configuração declarada no formato sentinel.ai.v1. Não executa modelos nem ferramentas e não testa resistência a prompt injection, vazamento por inferência ou comportamento do modelo.');
}
