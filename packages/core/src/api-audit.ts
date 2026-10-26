import {ARTIFACT_LIMITS,ArtifactAnalysisError,type ArtifactAnalysisReport} from './artifact-types.js';
import {addFinding,fact,list,objectEntries,parseJson,record,text,type JsonObject} from './artifact-support.js';

const METHODS=new Set(['get','put','post','delete','options','head','patch','trace']);
const SCHEMA_TYPES=new Set(['null','boolean','object','array','number','string','integer']);
const own=(value:object,key:string)=>Object.prototype.hasOwnProperty.call(value,key);
interface Scheme {type:string;scopes:Set<string>;}

/** Passive configuration audit. Never fetches URLs, opens paths, or executes document content. */
export function analyzeOpenApi(content:string,report:ArtifactAnalysisReport):void {
  if(typeof content!=='string'||!content.length||Buffer.byteLength(content,'utf8')>ARTIFACT_LIMITS.bytes||content.includes('\0'))throw new ArtifactAnalysisError('OpenAPI deve ser JSON UTF-8 de até 1 MiB, sem NUL.');
  const root=record(parseJson(content),'documento OpenAPI');
  const version=text(root.openapi,'openapi',20);
  if(!/^3\.[01]\.\d{1,3}$/.test(version))throw new ArtifactAnalysisError('Somente OpenAPI 3.0.x e 3.1.x em JSON são suportados.');
  const v31=version.startsWith('3.1.');
  const info=record(root.info,'info');
  for(const field of ['title','version'])if(!text(info[field],'metadado info',1024).trim())throw new ArtifactAnalysisError('info exige title e version não vazios.');
  if(root.paths===undefined&&(!v31||(root.components===undefined&&root.webhooks===undefined)))throw new ArtifactAnalysisError('Documento OpenAPI sem paths ou estrutura 3.1 equivalente.');
  report.format=`openapi-${version}`;
  let operations=0,anonymous=0,unspecified=0,unresolved=0,relativeUrls=0,bodySchemas=0,emptyOAuthScopes=0,work=0;
  const schemes=new Map<string,Scheme|undefined>();
  const reviewLocations=new Set<string>();
  const knownDialects=new Set(['https://spec.openapis.org/oas/3.1/dialect/base','https://json-schema.org/draft/2020-12/schema']);
  const customDialect=root.jsonSchemaDialect!==undefined&&!knownDialects.has(text(root.jsonSchemaDialect,'jsonSchemaDialect',4096));
  const tick=()=>{if(++work>ARTIFACT_LIMITS.nodes)throw new ArtifactAnalysisError('Limite de trabalho da auditoria OpenAPI excedido.');};
  function finding(ruleId:string,location:string,title:string,recommendation:string,evidence:unknown,severity:'info'|'low'|'medium'='low') {
    addFinding(report,{ruleId,location,title,recommendation,severity,confidence:'high'},evidence);
  }
  function review(location:string,evidence:unknown) {
    if(reviewLocations.has(location))return;
    reviewLocations.add(location);unresolved++;
    finding('API-REFERENCE-001',location,'Referência ou composição exige revisão no documento completo','Forneça a definição local sem ciclos ou valide manualmente a composição. Nenhuma referência externa foi acessada e este trecho não recebe conclusão de segurança.',evidence,'info');
  }
  function resolve(value:unknown,location:string,seen=new Set<string>()):unknown {
    tick();
    if(typeof value==='boolean')return value;
    const node=record(value,'objeto referenciado');
    if(node.$ref===undefined)return node;
    const ref=text(node.$ref,'referência',4096);
    if(Object.keys(node).some(key=>!['$ref','description','summary'].includes(key))){review(location,node);return undefined;}
    if(!ref.startsWith('#/')||seen.has(ref)||seen.size>=32){review(location,node);return undefined;}
    let decoded:string;
    try{decoded=decodeURIComponent(ref.slice(2));}catch{throw new ArtifactAnalysisError('Fragmento de referência local inválido.');}
    const parts=decoded.split('/');
    let target:unknown=root;
    for(const part of parts){
      if(/~(?:[^01]|$)/.test(part))throw new ArtifactAnalysisError('JSON Pointer local inválido.');
      const key=part.replace(/~1/g,'/').replace(/~0/g,'~');
      if(target===null||typeof target!=='object'||!own(target,key)){review(location,node);return undefined;}
      target=(target as Record<string,unknown>)[key];
    }
    const next=new Set(seen);next.add(ref);
    return resolve(target,location,next);
  }
  function checkUrl(raw:unknown,location:string,kind:'server'|'auth') {
    const url=text(raw,'URL declarada',8192);
    if(!url||/[\r\n\t ]/.test(url))throw new ArtifactAnalysisError('URL declarada inválida.');
    let parsed:URL;
    try{parsed=new URL(url,'https://openapi-audit.invalid/');}catch{throw new ArtifactAnalysisError('URL declarada inválida.');}
    if(!/^[a-z][a-z0-9+.-]*:/i.test(url)){relativeUrls++;return;}
    if(parsed.protocol==='http:')finding(kind==='server'?'API-SERVER-HTTP-001':'API-AUTH-HTTP-001',location,kind==='server'?'Documento declara servidor HTTP sem TLS':'Documento declara endpoint de autenticação HTTP sem TLS','Declare HTTPS e confirme a configuração implantada em uma validação autorizada. A URL e seus parâmetros não são copiados para o relatório.',{url},'medium');
    if(!['http:','https:'].includes(parsed.protocol))finding('API-URL-SCHEME-001',location,'URL utiliza um protocolo fora da análise HTTP','Revise o protocolo e a finalidade da URL. Nenhuma URL foi consultada.',{url},'info');
  }
  function servers(raw:unknown,location:string) {
    if(raw===undefined)return;
    list(raw,'servers').forEach((value,index)=>{
      const server=record(value,'server'),at=`${location}/${index}`;
      const template=text(server.url,'server.url',8192);
      const variables=server.variables===undefined?{}:record(server.variables,'server.variables');
      for(const [,rawVariable] of objectEntries(variables,'server.variables')){
        const variable=record(rawVariable,'variável de servidor');text(variable.default,'default de servidor',1024);
        if(variable.enum!==undefined){const choices=list(variable.enum,'enum de servidor').map(item=>text(item,'enum de servidor',1024));if(!choices.length||!choices.includes(variable.default as string))throw new ArtifactAnalysisError('Default de servidor deve constar no enum não vazio.');}
      }
      const expanded=template.replace(/\{([^{}]+)\}/g,(_match,name:string)=>{
        if(!own(variables,name))throw new ArtifactAnalysisError('Variável de servidor sem definição.');
        return record(variables[name],'variável de servidor').default as string;
      });
      if(expanded.length>8192||/[{}]/.test(expanded))throw new ArtifactAnalysisError('Template de servidor inválido ou acima do limite.');
      checkUrl(expanded,`${at}/url`,'server');
      if(Object.keys(variables).length)finding('API-SERVER-VARIABLE-001',at,'Servidor parametrizado analisado somente com valores padrão','Confira as substituições autorizadas no ambiente implantado. Alternativas de variáveis não são expandidas combinatoriamente.',server,'info');
    });
  }
  const components=root.components===undefined?{}:record(root.components,'components');
  const rawSchemes=components.securitySchemes===undefined?[]:objectEntries(components.securitySchemes,'securitySchemes');
  rawSchemes.forEach(([name,value],index)=>{
    if(!/^[a-zA-Z0-9._-]{1,240}$/.test(name))throw new ArtifactAnalysisError('Nome de componente de segurança inválido.');
    const at=`/components/securitySchemes/#${index+1}`,resolved=resolve(value,at);
    if(resolved===undefined){schemes.set(name,undefined);return;}
    const node=record(resolved,'security scheme'),type=text(node.type,'tipo de security scheme',40),scopes=new Set<string>();
    if(!['apiKey','http','oauth2','openIdConnect',...(v31?['mutualTLS']:[])].includes(type))throw new ArtifactAnalysisError('Tipo de security scheme inválido para esta versão OpenAPI.');
    if(type==='apiKey'){
      if(!text(node.name,'nome de API key',240)||!['header','cookie','query'].includes(String(node.in)))throw new ArtifactAnalysisError('API key exige name e in válidos.');
      if(node.in==='query')finding('API-QUERY-KEY-001',at,'Esquema declara API key em parâmetro de URL','Prefira um header apropriado e revise logs e caches. A declaração não demonstra que uma credencial foi efetivamente exposta.',node);
    }
    if(type==='http'&&!text(node.scheme,'esquema HTTP',100).trim())throw new ArtifactAnalysisError('Esquema HTTP ausente.');
    if(type==='openIdConnect')checkUrl(node.openIdConnectUrl,`${at}/openIdConnectUrl`,'auth');
    if(type==='oauth2'){
      const flows=objectEntries(node.flows,'OAuth flows').filter(([key])=>!key.startsWith('x-'));
      if(!flows.length)finding('API-OAUTH-FLOW-001',`${at}/flows`,'Esquema OAuth2 sem fluxo documentado','Documente os fluxos realmente aceitos para permitir revisão do contrato.',node,'info');
      flows.forEach(([flowName,value],flowIndex)=>{
        if(!['implicit','password','clientCredentials','authorizationCode'].includes(flowName))throw new ArtifactAnalysisError('Fluxo OAuth2 desconhecido.');
        const flow=record(value,'OAuth flow'),where=`${at}/flows/#${flowIndex+1}`;
        if(['implicit','authorizationCode'].includes(flowName))checkUrl(flow.authorizationUrl,`${where}/authorizationUrl`,'auth');
        if(['password','clientCredentials','authorizationCode'].includes(flowName))checkUrl(flow.tokenUrl,`${where}/tokenUrl`,'auth');
        if(flow.refreshUrl!==undefined)checkUrl(flow.refreshUrl,`${where}/refreshUrl`,'auth');
        const entries=objectEntries(flow.scopes,'OAuth scopes');
        if(!entries.length)emptyOAuthScopes++;
        for(const [scope,description] of entries){text(scope,'nome de scope',512);text(description,'descrição de scope',4096);scopes.add(scope);}
      });
    }
    schemes.set(name,{type,scopes});
  });
  function security(value:unknown,location:string):{anonymous:boolean;empty:boolean} {
    const alternatives=list(value,'security');
    let allowsAnonymous=alternatives.length===0;
    alternatives.forEach((alternative,index)=>{
      const requirements=objectEntries(alternative,'security requirement');
      if(!requirements.length)allowsAnonymous=true;
      requirements.forEach(([name,rawScopes],schemeIndex)=>{
        const scopes=list(rawScopes,'security scopes').map(item=>text(item,'scope requerido',512));
        const at=`${location}/${index}/#${schemeIndex+1}`;
        if(!schemes.has(name)){finding('API-SCHEME-UNKNOWN-001',at,'Requisito aponta para um esquema de segurança não declarado','Declare o esquema em components.securitySchemes e confirme a política efetiva. Um nome desconhecido não é tratado como acesso anônimo.',alternative,'medium');return;}
        const scheme=schemes.get(name);
        if(!scheme)return;
        if(!v31&&!['oauth2','openIdConnect'].includes(scheme.type)&&scopes.length)throw new ArtifactAnalysisError('OpenAPI 3.0 exige array vazio para requisitos que não sejam OAuth2/OpenID.');
        if(scheme.type==='oauth2'&&scopes.some(scope=>!scheme.scopes.has(scope)))finding('API-OAUTH-SCOPE-001',at,'Requisito OAuth2 cita scope ausente nos fluxos documentados','Revise a consistência entre scopes exigidos e publicados. Não há consulta ao servidor de autorização.',alternative);
      });
    });
    return {anonymous:allowsAnonymous,empty:alternatives.length===0};
  }
  const globalSecurity=root.security===undefined?undefined:security(root.security,'/security');
  servers(root.servers,'/servers');
  function schema(value:unknown,location:string,trail=new Set<object>()) {
    tick();bodySchemas++;
    if(customDialect){review(location,{schema:value,dialect:root.jsonSchemaDialect});return;}
    const resolved=resolve(value,location);
    if(resolved===undefined)return;
    if(typeof resolved==='boolean'){
      if(!v31)throw new ArtifactAnalysisError('Schema booleano exige OpenAPI 3.1.');
      if(resolved)finding('API-BODY-FREEFORM-001',location,'Corpo usa schema que aceita qualquer valor','Defina tipos e limites adequados, considerando também o limite de bytes no servidor.',resolved);
      return;
    }
    const node=record(resolved,'request schema');
    if(node.readOnly===true)return;
    if(trail.has(node)){review(location,node);return;}
    if(trail.size>=32)throw new ArtifactAnalysisError('Schema referenciado profundo demais.');
    const next=new Set(trail);next.add(node);
    if(['allOf','anyOf','oneOf','not','if','then','else','$dynamicRef','$id','unevaluatedProperties','unevaluatedItems','patternProperties','dependentSchemas','contains','propertyNames'].some(key=>node[key]!==undefined)
      ||(node.$schema!==undefined&&!knownDialects.has(text(node.$schema,'dialeto de schema',4096)))){review(location,node);return;}
    for(const key of ['maxLength','maxItems','maxProperties'])if(node[key]!==undefined&&(!Number.isSafeInteger(node[key])||(node[key] as number)<0))throw new ArtifactAnalysisError('Limite de schema deve ser inteiro não negativo seguro.');
    if(node.enum!==undefined&&!list(node.enum,'enum de schema').length)throw new ArtifactAnalysisError('enum de schema não pode ser vazio.');
    const rawTypes=node.type===undefined?[]:Array.isArray(node.type)?list(node.type,'tipos de schema'): [node.type];
    if(!v31&&Array.isArray(node.type))throw new ArtifactAnalysisError('Array de tipos de schema exige OpenAPI 3.1.');
    const types=rawTypes.map(value=>text(value,'tipo de schema',30));
    if(new Set(types).size!==types.length||types.some(type=>!SCHEMA_TYPES.has(type)||(!v31&&type==='null')))throw new ArtifactAnalysisError('Tipo de schema inválido.');
    if(!types.length){
      if(node.enum===undefined&&(!v31||node.const===undefined))finding('API-BODY-TYPE-001',location,'Schema de corpo não restringe um tipo explícito','Revise os tipos aceitos e os limites do corpo. Esta análise não substitui validação JSON Schema.',node,'info');
    }
    const finiteValues=Array.isArray(node.enum)||(v31&&own(node,'const'));
    if(types.includes('string')&&node.maxLength===undefined&&!finiteValues)finding('API-STRING-LIMIT-001',location,'String de requisição sem maxLength declarado','Defina comprimento máximo adequado ou documente o controle equivalente no servidor. Ausência no contrato não comprova ausência em runtime.',node);
    if(types.includes('array')){
      if(node.maxItems===undefined&&!finiteValues&&!(v31&&node.items===false&&Array.isArray(node.prefixItems)))finding('API-ARRAY-LIMIT-001',location,'Array de requisição sem maxItems declarado','Defina a quantidade máxima de elementos adequada ao uso e confirme o limite implementado.',node);
      if(node.items!==undefined)schema(node.items,`${location}/items`,next);
      if(node.prefixItems!==undefined){if(!v31)throw new ArtifactAnalysisError('prefixItems exige OpenAPI 3.1.');list(node.prefixItems,'prefixItems').forEach((item,index)=>schema(item,`${location}/prefixItems/${index}`,next));}
    }
    if(types.includes('object')||node.properties!==undefined){
      const properties=node.properties===undefined?[]:objectEntries(node.properties,'schema properties');
      if(types.includes('object')&&node.maxProperties===undefined&&!finiteValues&&node.additionalProperties!==false)finding('API-OBJECT-LIMIT-001',location,'Objeto permite propriedades adicionais sem maxProperties declarado','Revise propriedades adicionais e quantidade máxima. Limites externos ao documento precisam de validação separada.',node);
      properties.forEach(([,property],index)=>schema(property,`${location}/properties/#${index+1}`,next));
      if(node.additionalProperties!==undefined&&typeof node.additionalProperties!=='boolean')schema(node.additionalProperties,`${location}/additionalProperties`,next);
    }
  }
  function requestBody(value:unknown,location:string) {
    const resolved=resolve(value,location);if(resolved===undefined)return;
    const body=record(resolved,'requestBody');
    if(body.required!==undefined&&typeof body.required!=='boolean')throw new ArtifactAnalysisError('requestBody.required deve ser booleano.');
    const media=objectEntries(body.content,'requestBody.content');
    if(!media.length)throw new ArtifactAnalysisError('requestBody.content deve ter ao menos um media type.');
    media.forEach(([name,value],index)=>{
      if(!/^[^\s/]+\/[^\s/]+$/.test(name))throw new ArtifactAnalysisError('Media type de corpo inválido.');
      const entry=record(value,'media type'),at=`${location}/content/#${index+1}/schema`;
      if(entry.schema===undefined)finding('API-BODY-SCHEMA-001',at,'Corpo documentado sem schema','Documente tipos e limites de entrada e confirme a validação no serviço.',entry);
      else schema(entry.schema,at);
    });
  }
  const paths=root.paths===undefined?[]:objectEntries(root.paths,'paths');
  paths.forEach(([path,value],pathIndex)=>{
    if(path.startsWith('x-'))return;
    if(!path.startsWith('/')||/[\x00-\x1f\x7f?#]/.test(path)||path.length>4096)throw new ArtifactAnalysisError('Path OpenAPI deve ser caminho de template sem query ou fragmento.');
    const at=`/paths/#${pathIndex+1}`,resolved=resolve(value,at);if(resolved===undefined)return;
    const item=record(resolved,'path item');
    servers(item.servers,`${at}/servers`);
    for(const [method,value] of objectEntries(item,'path item')){
      if(['summary','description','parameters','servers'].includes(method)||method.startsWith('x-'))continue;
      if(!METHODS.has(method))throw new ArtifactAnalysisError('Campo de path item não reconhecido.');
      if(++operations>ARTIFACT_LIMITS.records)throw new ArtifactAnalysisError('Mais de 2000 operações OpenAPI.');
      const operation=record(value,'operation'),where=`${at}/${method}`;
      const effective=operation.security===undefined?globalSecurity:security(operation.security,`${where}/security`);
      if(effective?.anonymous){
        anonymous++;
        finding('API-ANONYMOUS-001',`${where}/security`,effective.empty?'Operação sem requisito de autenticação no contrato':'Operação permite alternativa anônima no contrato','Confirme se a operação é intencionalmente pública. Se precisar de proteção, corrija o contrato e teste a autorização efetiva. A declaração não comprova acesso indevido.',{global:operation.security===undefined,security:operation.security??root.security},'info');
      }else if(effective===undefined){
        unspecified++;
        finding('API-SECURITY-UNSPECIFIED-001',`${where}/security`,'Operação sem declaração de segurança aplicável','Documente o requisito ou a intenção pública. Ausência de declaração não comprova ausência de autenticação no serviço.',{operation,globalSecurity:root.security},'info');
      }
      servers(operation.servers,`${where}/servers`);
      if(operation.requestBody!==undefined)requestBody(operation.requestBody,`${where}/requestBody`);
      if(operation.callbacks!==undefined){record(operation.callbacks,'callbacks');review(`${where}/callbacks`,operation.callbacks);}
    }
  });
  if(root.webhooks!==undefined){record(root.webhooks,'webhooks');review('/webhooks',root.webhooks);}
  fact(report,'Operações HTTP analisadas',operations);fact(report,'Esquemas de segurança declarados',schemes.size);
  fact(report,'Operações com acesso anônimo declarado',anonymous);fact(report,'Operações sem declaração de segurança',unspecified);
  fact(report,'Schemas de requisição examinados',bodySchemas);fact(report,'Trechos que exigem revisão complementar',unresolved);
  fact(report,'URLs relativas com transporte dependente do ambiente',relativeUrls);fact(report,'Fluxos OAuth2 com mapa de scopes vazio válido',emptyOAuthScopes);
  report.limitations.push('Auditoria passiva do contrato OpenAPI 3.0/3.1 JSON fornecido; não faz requisições, descoberta, resolução DNS, leitura de arquivos ou consulta a referências externas. Não testa BOLA, BFLA, SSRF, injeção, exploração, rate limit ou autenticação efetiva.',
    'Herança de security considera o nível global e a substituição por operação. Alternativas do array são OR; requisitos no mesmo objeto são AND. Scopes OAuth2 vazios podem ser válidos e não indicam acesso anônimo.',
    'Validação estrutural parcial, não certificação completa de OpenAPI/JSON Schema. Limites de entrada cobrem schemas simples de requestBody; parâmetros, respostas, callbacks, webhooks, composições complexas e dialetos customizados exigem revisão própria. Schemas recursivos e referências não resolvidas são sinalizados.',
    'Servidores são inspecionados onde declarados, inclusive definições que podem ser substituídas em operações. URLs relativas dependem da base de implantação; variáveis usam somente defaults. Acesso público pode ser intencional. Ausência de achados não atesta segurança.',
    'Localizações usam a ordem de inserção com índices #1, #2 etc., preservando o contexto sem copiar caminhos, nomes de componentes, scopes, exemplos, URLs ou segredos. Evidências permanecem identificadas por hash.');
}
