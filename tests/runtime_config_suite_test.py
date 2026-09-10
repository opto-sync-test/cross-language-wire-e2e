from __future__ import annotations
import os,re,tomllib,unittest
ENV_KEY=re.compile(r"^[A-Z_][A-Z0-9_]{1,127}$"); MW_KEYS={"schema_version","repository_mode","allow_overlapping_roots","default_target","targets"}; T_KEYS={"name","role","roots","enabled","middleware","stack_config","propagate_headers"}
def p(s):
 v=tomllib.loads(s)
 if not isinstance(v,dict): raise ValueError("root")
 return v
def req(x,c):
 if not x: raise ValueError(c)
def env(v): req(isinstance(v,str) and ENV_KEY.fullmatch(v) is not None and "://" not in v and "=" not in v,"env-name"); return v
def mw(v):
 req(set(v)<=MW_KEYS and v.get("schema_version")==1,"mw-shape"); mode=v.get("repository_mode"); req(mode in {"client-only","server-only","hybrid"},"mw-mode"); ts=v.get("targets"); req(isinstance(ts,list) and ts,"mw-targets"); roles=set(); roots={"client":set(),"server":set()}; names=set()
 for t in ts:
  req(isinstance(t,dict) and set(t)<=T_KEYS,"mw-target"); n,r,m=t.get("name"),t.get("role"),t.get("middleware"); req(isinstance(n,str) and n and n not in names,"mw-name"); names.add(n); req(r in roots,"mw-role"); roles.add(r); rs=t.get("roots"); req(isinstance(rs,list) and rs,"mw-roots"); roots[r].update(rs); req(m in {"stack","propagation-only","disabled"},"mw-kind")
  if r=="client":
   req(m!="stack" and "stack_config" not in t,"client-stack")
   if m=="propagation-only": req("traceparent" in t.get("propagate_headers",[]),"traceparent")
  if m=="stack": req(r=="server" and isinstance(t.get("stack_config"),str),"server-stack")
 req(roles==({"client"} if mode=="client-only" else {"server"} if mode=="server-only" else {"client","server"}),"role-leak")
 if mode=="hybrid" and roots["client"]&roots["server"]: req(v.get("allow_overlapping_roots") is True,"overlap")
def rl(v):
 req(v.get("schemaVersion")=="ores.rate-limit.config.v1","rl-version"); layout=v.get("layout"); req(layout in {"client-only","server-only","combined"},"rl-layout")
 if layout in {"client-only","combined"}: req(isinstance(v.get("client"),dict) and not ({"redisUrlEnv","keyHmacEnv","backend"}&set(v["client"])),"rl-client-leak")
 if layout in {"server-only","combined"}:
  req(isinstance(v.get("server"),dict),"rl-server")
  for k in ("redisUrlEnv","keyHmacEnv"):
   if k in v["server"]: env(v["server"][k])
 ps=v.get("policies"); req(isinstance(ps,list) and ps,"rl-policy")
 for x in ps: req(x.get("enforcementMode") in {"observe-only","disabled"} and x.get("consistencyMode")=="advisory","rl-staging")
def lru(v):
 req(v.get("protocol")=="ores.lru-config.v1","lru-version"); roles=v.get("roles"); req(isinstance(roles,list) and roles and set(roles)<={"client","server"},"lru-roles")
 if "redis" in v: env(v["redis"].get("urlEnv"))
 ids=set()
 for c in v.get("caches",[]):
  ident=(c.get("role"),c.get("name")); req(ident[0] in roles and ident[1] and ident not in ids,"lru-id"); ids.add(ident)
  if ident[0]=="client": req(c.get("syncMode")=="local_only","lru-client")
 req(ids,"lru-caches")
def auth(v,names):
 req(not ({".shared-auth.toml",".auth-shared.toml"}<=names),"auth-dual"); c=v.get("compatibility"); req(v.get("schema_version")==1 and isinstance(c,dict) and c.get("repository")=="https://github.com/shared-auth/shared-auth-interfaces" and re.fullmatch(r"[0-9a-f]{40}",c.get("commit",'')),"auth-provenance")
def domain(d,cli):
 f=d.get("flags2env"); req(d.get("version")==1 and d.get("strict") is True and isinstance(f,dict) and f.get("contract")==".cli-flags.toml" and f.get("require_audit") is True and f.get("precedence")=="argv-over-env","domain")
 secrets=set()
 for e in d.get("env",[]):
  k=env(e.get("key"))
  if e.get("secret") is True: req("default" not in e,"secret-default"); secrets.add(k)
 req(cli.get("env",{}).get("load") is False and cli.get("parse",{}).get("allow_unknown") is False,"f2e-strict"); req(not secrets&{x.get("env") for x in cli.get("flags",{}).values()},"secret-argv")
MW_C='''schema_version=1\nrepository_mode="client-only"\n[[targets]]\nname="c"\nrole="client"\nroots=["."]\nmiddleware="propagation-only"\npropagate_headers=["traceparent"]\n'''; MW_S='''schema_version=1\nrepository_mode="server-only"\n[[targets]]\nname="s"\nrole="server"\nroots=["."]\nmiddleware="disabled"\n'''; MW_H='''schema_version=1\nrepository_mode="hybrid"\nallow_overlapping_roots=true\n[[targets]]\nname="s"\nrole="server"\nroots=["."]\nmiddleware="disabled"\n[[targets]]\nname="c"\nrole="client"\nroots=["."]\nmiddleware="propagation-only"\npropagate_headers=["traceparent"]\n'''; MW_O=MW_H.replace('allow_overlapping_roots=true\n',''); MW_ST='''schema_version=1\nrepository_mode="client-only"\n[[targets]]\nname="c"\nrole="client"\nroots=["."]\nmiddleware="stack"\nstack_config="server.json"\n'''
RL_C='''schemaVersion="ores.rate-limit.config.v1"\nlayout="client-only"\n[client]\nroot="."\n[[policies]]\npolicyId="x"\nenforcementMode="observe-only"\nconsistencyMode="advisory"\n'''; RL_H='''schemaVersion="ores.rate-limit.config.v1"\nlayout="combined"\n[client]\nroot="."\n[server]\nroot="."\nkeyHmacEnv="ORES_RL_HMAC_KEY"\n[[policies]]\npolicyId="x"\nenforcementMode="observe-only"\nconsistencyMode="advisory"\n'''; RL_B=RL_C.replace('root="."','root="."\nredisUrlEnv="https://not-env.invalid"')
LRU_C='''protocol="ores.lru-config.v1"\nroles=["client"]\n[[caches]]\nname="x"\nrole="client"\nsyncMode="local_only"\n'''; LRU_H='''protocol="ores.lru-config.v1"\nroles=["client","server"]\n[redis]\nurlEnv="REDIS_URL"\n[[caches]]\nname="x"\nrole="client"\nsyncMode="local_only"\n[[caches]]\nname="x"\nrole="server"\nsyncMode="read_only"\n'''; LRU_B=LRU_H.replace('urlEnv="REDIS_URL"','urlEnv="https://not-env.invalid"')
AUTH='''schema_version=1\n[compatibility]\nrepository="https://github.com/shared-auth/shared-auth-interfaces"\ncommit="52b7ac7fbf0c7c169684f613eda923f3aa6c82e9"\n'''; D='''version=1\nmode="hybrid"\nstrict=true\n[flags2env]\ncontract=".cli-flags.toml"\nrequire_audit=true\nprecedence="argv-over-env"\n[[env]]\nname="api"\nkey="API_BASE"\nkind="url"\nrequired=false\nsecret=false\ndefault="http://127.0.0.1"\n[[env]]\nname="token"\nkey="AUTH_TOKEN"\nkind="string"\nrequired=true\nsecret=true\n'''; C='''[env]\nload=false\n[parse]\nallow_unknown=false\n[flags.api]\nenv="API_BASE"\ntype="string"\n'''; CB=C+'''[flags.token]\nenv="AUTH_TOKEN"\ntype="string"\n'''
class T(unittest.TestCase):
 def test_org(self): self.assertTrue(os.environ.get("TEST_GITHUB_ORG","").endswith("-test"))
 def test_mw(self):
  for x in (MW_C,MW_S,MW_H): mw(p(x))
  for x in (MW_O,MW_ST):
   with self.assertRaises(ValueError): mw(p(x))
 def test_rl(self):
  rl(p(RL_C)); rl(p(RL_H))
  with self.assertRaises(ValueError): rl(p(RL_B))
 def test_lru(self):
  lru(p(LRU_C)); lru(p(LRU_H))
  with self.assertRaises(ValueError): lru(p(LRU_B))
 def test_auth(self):
  auth(p(AUTH),{".auth-shared.toml"})
  with self.assertRaises(ValueError): auth(p(AUTH),{".auth-shared.toml",".shared-auth.toml"})
 def test_flags(self):
  domain(p(D),p(C))
  with self.assertRaises(ValueError): domain(p(D),p(CB))
  r=lambda d,e,a:a.get("K",e.get("K",d)); self.assertEqual((r("d",{},{}),r("d",{"K":"e"},{}),r("d",{"K":"e"},{"K":"a"})),("d","e","a"))
if __name__=="__main__": unittest.main()
