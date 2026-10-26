import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyzeOpenApi} from '../src/api-audit.js';
import {sha256} from '../src/scanner.js';
import {ArtifactAnalysisError,ARTIFACT_LIMITS,type ArtifactAnalysisReport} from '../src/artifact-types.js';

const bearer={type:'http',scheme:'bearer'};
const operation=(extra:Record<string,unknown>={})=>({responses:{'200':{description:'Response'}},...extra});
function document(version='3.1.1'):any {return {openapi:version,info:{title:'Fixture',version:'1.0.0'},servers:[{url:'https://service.example'}],components:{securitySchemes:{bearer}},security:[{bearer:[]}],paths:{'/items':{get:operation()}}};}
function run(value:unknown):ArtifactAnalysisReport {
  const content=typeof value==='string'?value:JSON.stringify(value);
  const report:ArtifactAnalysisReport={schemaVersion:'1.0',engine:'Sentinel Artifact Analysis',ruleSetVersion:'1.0.0',kind:'api' as ArtifactAnalysisReport['kind'],input:{name:'openapi.json',mediaType:'application/json',sha256:sha256(content),bytes:Buffer.byteLength(content)},format:'',summary:'',findings:[],facts:[],limitations:[]};
  analyzeOpenApi(content,report);return report;
}
const rules=(report:ArtifactAnalysisReport)=>report.findings.map(item=>item.ruleId);
const metric=(report:ArtifactAnalysisReport,label:string)=>report.facts.find(item=>item.label===label)?.value;

test('OpenAPI 3.0/3.1 safe fixture keeps inherited authentication and simple finite request schemas',()=>{
  for(const version of ['3.0.0','3.0.4','3.1.0','3.1.1']){
    const input=document(version);
    input.paths['/items'].post=operation({requestBody:{content:{'application/json':{schema:{type:'object',additionalProperties:false,properties:{name:{type:'string',maxLength:100},ids:{type:'array',maxItems:10,items:{type:'integer'}}}}}}}});
    const result=run(input);assert.equal(result.format,`openapi-${version}`);assert.deepEqual(result.findings,[]);assert.equal(metric(result,'Operações HTTP analisadas'),2);
    assert.ok(result.limitations.some(item=>item.includes('BOLA')));
  }
});

test('security inherits globally, operation overrides replace it, arrays are OR and members are AND',()=>{
  const input=document();input.components.securitySchemes.key={type:'apiKey',in:'header',name:'X-Key'};
  input.security=[{bearer:[],key:[]}];
  input.paths={
    '/inherited':{get:operation()},
    '/and':{get:operation({security:[{bearer:[],key:[]}]})},
    '/or':{get:operation({security:[{bearer:[]},{key:[]}]})},
    '/removed':{get:operation({security:[]})},
    '/optional':{get:operation({security:[{bearer:[]},{}]})},
  };
  const result=run(input);assert.equal(metric(result,'Operações com acesso anônimo declarado'),2);
  assert.deepEqual(result.findings.filter(item=>item.ruleId==='API-ANONYMOUS-001').map(item=>item.location),['/paths/#4/get/security','/paths/#5/get/security']);
  assert.ok(result.findings.every(item=>item.severity==='info'));
  input.security=[];input.paths={'/protected':{get:operation({security:[{bearer:[]}]})}};
  assert.ok(!rules(run(input)).includes('API-ANONYMOUS-001'));
});

test('missing declaration is separate from explicit anonymous access and unknown schemes are not treated as anonymous',()=>{
  const input=document();delete input.security;
  assert.deepEqual(rules(run(input)),['API-SECURITY-UNSPECIFIED-001']);
  input.security=[{missing:[]}];const result=run(input);
  assert.deepEqual(rules(result),['API-SCHEME-UNKNOWN-001']);assert.equal(metric(result,'Operações com acesso anônimo declarado'),0);
  input.security=[{missing:[]},{}];assert.ok(rules(run(input)).includes('API-ANONYMOUS-001'));
});

test('HTTP URLs and query API keys produce configuration findings without copying paths, credentials, names or query values',()=>{
  const input=document();
  input.components.securitySchemes={PRIVATE_SCHEME:{type:'apiKey',in:'query',name:'PRIVATE_KEY_NAME'},oauth:{type:'oauth2',flows:{clientCredentials:{tokenUrl:'http://user:PRIVATE_PASSWORD@auth.example/token?secret=PRIVATE_QUERY',scopes:{}}}}};
  input.security=[{PRIVATE_SCHEME:[]}];
  input.servers=[{url:'http://user:PRIVATE_PASSWORD@service.example/?secret=PRIVATE_QUERY'}];
  input.paths={'/PRIVATE_PATH':{post:operation({requestBody:{content:{'application/json':{schema:{type:'string',example:'PRIVATE_EXAMPLE'}}}}})}};
  const result=run(input),serialized=JSON.stringify(result);
  for(const rule of ['API-QUERY-KEY-001','API-SERVER-HTTP-001','API-AUTH-HTTP-001','API-STRING-LIMIT-001'])assert.ok(rules(result).includes(rule));
  for(const secret of ['PRIVATE_SCHEME','PRIVATE_KEY_NAME','PRIVATE_PASSWORD','PRIVATE_QUERY','PRIVATE_PATH','PRIVATE_EXAMPLE','service.example','auth.example'])assert.ok(!serialized.includes(secret),secret);
  assert.ok(result.findings.every(item=>/^[a-f0-9]{64}$/.test(item.evidenceHash)));
});

test('empty OAuth scopes are valid and never imply anonymous access; unknown declared scopes remain inconsistencies',()=>{
  const input=document();input.components.securitySchemes={oauth:{type:'oauth2',flows:{clientCredentials:{tokenUrl:'https://auth.example/token',scopes:{}}}}};input.security=[{oauth:[]}];
  const result=run(input);assert.deepEqual(result.findings,[]);assert.equal(metric(result,'Fluxos OAuth2 com mapa de scopes vazio válido'),1);
  input.security=[{oauth:['undeclared']}];assert.deepEqual(rules(run(input)),['API-OAUTH-SCOPE-001']);
  input.components.securitySchemes.oauth.flows.clientCredentials.scopes={undeclared:'Description'};assert.deepEqual(run(input).findings,[]);
});

test('OpenAPI 3.0 non-OAuth requirements reject scope/role values while 3.1 role arrays are accepted',()=>{
  const input=document('3.0.4');input.security=[{bearer:['operator']}];assert.throws(()=>run(input),ArtifactAnalysisError);
  input.openapi='3.1.1';assert.deepEqual(run(input).findings,[]);
  input.components.securitySchemes.mtls={type:'mutualTLS'};input.security=[{mtls:[]}];assert.deepEqual(run(input).findings,[]);
  input.openapi='3.0.4';assert.throws(()=>run(input),ArtifactAnalysisError);
});

test('local JSON pointers resolve security schemes, path items and request bodies without external access',()=>{
  const input=document();
  input.components.securitySchemes.alias={$ref:'#/components/securitySchemes/bearer'};input.security=[{alias:[]}];
  input.components.schemas={'Payload/Name~':{type:'string',maxLength:50}};
  input.components.requestBodies={payload:{content:{'application/json':{schema:{$ref:'#/components/schemas/Payload~1Name~0'}}}}};
  input.components.pathItems={reused:{post:operation({requestBody:{$ref:'#/components/requestBodies/payload'}})}};
  input.paths={'/reused':{$ref:'#/components/pathItems/reused'}};
  assert.deepEqual(run(input).findings,[]);
});

test('external, missing, cyclic and ambiguous sibling references require review and never fetch',()=>{
  const originalFetch=globalThis.fetch;let fetched=false;
  globalThis.fetch=(async()=>{fetched=true;throw new Error('must not fetch');}) as typeof fetch;
  try{
    for(const ref of ['https://external.example/spec.json#/schema','file:///PRIVATE_FILE','#/components/schemas/missing','#anchor']){
      const input=document();input.paths['/items'].post=operation({requestBody:{content:{'application/json':{schema:{$ref:ref}}}}});
      assert.ok(rules(run(input)).includes('API-REFERENCE-001'));
    }
    const input=document();input.components.schemas={node:{type:'object',additionalProperties:false,properties:{next:{$ref:'#/components/schemas/node'}}}};
    input.paths['/items'].post=operation({requestBody:{content:{'application/json':{schema:{$ref:'#/components/schemas/node'}}}}});
    assert.ok(rules(run(input)).includes('API-REFERENCE-001'));
    input.components.schemas={a:{$ref:'#/components/schemas/b'},b:{$ref:'#/components/schemas/a'}};
    input.paths['/items'].post.requestBody.content['application/json'].schema={$ref:'#/components/schemas/a'};
    assert.ok(rules(run(input)).includes('API-REFERENCE-001'));
    input.paths['/items'].post.requestBody.content['application/json'].schema={$ref:'#/components/schemas/a',maxLength:40};
    assert.deepEqual(rules(run(input)),['API-REFERENCE-001']);
    input.components.securitySchemes.external={$ref:'https://external.example/security'};input.security=[{external:[]}];
    assert.ok(!rules(run(input)).includes('API-SCHEME-UNKNOWN-001'));
    assert.equal(fetched,false);
  }finally{globalThis.fetch=originalFetch;}
});

test('simple request size declarations are reviewed conservatively for strings, arrays, free objects and absent schemas',()=>{
  const input=document();input.paths['/items'].post=operation({requestBody:{content:{'application/json':{schema:{type:'object',properties:{name:{type:'string'},list:{type:'array',items:{type:'integer'}}}}},'text/plain':{}}}});
  const found=rules(run(input));for(const rule of ['API-STRING-LIMIT-001','API-ARRAY-LIMIT-001','API-OBJECT-LIMIT-001','API-BODY-SCHEMA-001'])assert.ok(found.includes(rule));
  input.paths['/items'].post.requestBody.content={'application/json':{schema:{type:'string',enum:['one','two']}}};assert.deepEqual(run(input).findings,[]);
  input.paths['/items'].post.requestBody.content['application/json'].schema={type:'array',prefixItems:[{type:'string',maxLength:8}],items:false};assert.deepEqual(run(input).findings,[]);
  input.paths['/items'].post.requestBody.content['application/json'].schema=false;assert.deepEqual(run(input).findings,[]);
  input.paths['/items'].post.requestBody.content['application/json'].schema=true;assert.deepEqual(rules(run(input)),['API-BODY-FREEFORM-001']);
});

test('composition and callback/webhook coverage are explicit without false unbounded-schema claims',()=>{
  const input=document();input.paths['/items'].post=operation({requestBody:{content:{'application/json':{schema:{allOf:[{type:'string'},{maxLength:50}]}}}},callbacks:{onData:{}}});input.webhooks={incoming:{}};
  const result=run(input);assert.equal(result.findings.length,3);assert.ok(result.findings.every(item=>item.ruleId==='API-REFERENCE-001'));
});

test('custom dialects and pattern-based schemas require review; finite values and read-only properties do not create size alarms',()=>{
  const input=document();
  input.paths['/items'].post=operation({requestBody:{content:{'application/json':{schema:{type:'object',additionalProperties:false,properties:{generated:{type:'string',readOnly:true},fixed:{type:'array',enum:[[1,2],[3]]}}}}}}});
  assert.deepEqual(run(input).findings,[]);
  input.jsonSchemaDialect='https://custom.example/dialect';assert.deepEqual(rules(run(input)),['API-REFERENCE-001']);
  delete input.jsonSchemaDialect;input.paths['/items'].post.requestBody.content['application/json'].schema={type:'object',patternProperties:{'^item':{type:'string'}}};
  assert.deepEqual(rules(run(input)),['API-REFERENCE-001']);
});

test('relative server URLs are not labeled HTTP; variable defaults are bounded and alternate configurations require review',()=>{
  const input=document();input.servers=[{url:'/api'},{url:'//relative.example/api'}];assert.deepEqual(run(input).findings,[]);assert.equal(metric(run(input),'URLs relativas com transporte dependente do ambiente'),2);
  input.servers=[{url:'{protocol}://service.example',variables:{protocol:{default:'http',enum:['http','https']}}}];
  assert.deepEqual(rules(run(input)),['API-SERVER-HTTP-001','API-SERVER-VARIABLE-001']);
  input.servers[0].variables.protocol.default='https';assert.deepEqual(rules(run(input)),['API-SERVER-VARIABLE-001']);
  input.servers[0].variables.protocol.default='ftp';assert.throws(()=>run(input),ArtifactAnalysisError);
});

test('malformed selected structures are rejected without including attacker values in errors',()=>{
  const mutations=[
    (x:any)=>{x.openapi='3.2.1';},(x:any)=>{x.info=[];},(x:any)=>{x.paths=[];},(x:any)=>{x.paths={'bad?PRIVATE_VALUE':{}};},
    (x:any)=>{x.paths['/items'].get=null;},(x:any)=>{x.security={bearer:[]};},(x:any)=>{x.security=[{bearer:'PRIVATE_VALUE'}];},
    (x:any)=>{x.components.securitySchemes.bearer={type:'arbitrary-PRIVATE_VALUE'};},
    (x:any)=>{x.paths['/items'].security=[];},(x:any)=>{x.servers=[{url:'{missing}://example'}];},
    (x:any)=>{x.paths['/items'].post=operation({requestBody:{content:{'application/json':{schema:{type:'string',maxLength:-1}}}}});},
    (x:any)=>{x.components.securitySchemes.oauth={type:'oauth2',flows:{clientCredentials:{tokenUrl:'https://auth.example'}}};},
  ];
  for(const mutate of mutations){const input=document();mutate(input);assert.throws(()=>run(input),(error:unknown)=>error instanceof ArtifactAnalysisError&&!error.message.includes('PRIVATE_VALUE'));}
  assert.throws(()=>run('{"openapi":"3.1.1","openapi":"3.1.1"}'),/duplicadas/);
});

test('byte, depth, node, operation and finding limits fail closed',()=>{
  assert.throws(()=>run(' '.repeat(ARTIFACT_LIMITS.bytes+1)),/1 MiB/);
  const deep=document();deep['x-deep']=JSON.parse('['.repeat(50)+'0'+']'.repeat(50));assert.throws(()=>run(deep),/profundo/);
  const wide=document();wide['x-wide']=Array(30000).fill(0);assert.throws(()=>run(wide),/estrutural/);
  const paths=document();paths.paths=Object.fromEntries(Array.from({length:2001},(_,i)=>[`/p${i}`,{get:operation()}]));assert.throws(()=>run(paths),/2000/);
  const many=document();many.security=[];many.paths=Object.fromEntries(Array.from({length:501},(_,i)=>[`/p${i}`,{get:operation()}]));assert.throws(()=>run(many),/500 achados/);
});

test('analysis is deterministic and leaves input/report source bytes unchanged',()=>{
  const input=document();input.security=[];const serialized=JSON.stringify(input);const first=run(serialized),second=run(serialized);
  assert.deepEqual(first,second);assert.equal(JSON.stringify(input),serialized);assert.equal(first.input.sha256,sha256(serialized));
});
