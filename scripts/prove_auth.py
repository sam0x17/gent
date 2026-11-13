#!/usr/bin/env python3
"""Exercise the real native CLI against the private account proof's local fixture.

Requires a CLI built with test-auth-provider. Does not contact GitHub or open a
browser. The private proof may expose its two loopback servers through SSH.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--service',required=True)
    parser.add_argument('--github-origin',required=True)
    args=parser.parse_args()
    root=Path(tempfile.mkdtemp(prefix='gent-auth-cli-',dir='/tmp')).resolve()
    root.chmod(0o700)
    env=dict(os.environ,GENT_TEST_GITHUB_ORIGIN=args.github_origin)
    base=[str(args.binary.resolve()),'--json']
    secrets=[]
    print(f'CLI proof state: {root}',flush=True)

    def cli(home,*commands,code=0):
        result=subprocess.run(base+['--home',str(home),'auth',*commands],env=env,text=True,capture_output=True,timeout=45)
        assert result.returncode==code,('CLI exit',commands,result.returncode,code)
        assert all(secret not in result.stdout+result.stderr for secret in secrets),'credential printed'
        return json.loads(result.stdout) if result.stdout else None

    def http(url,data=None,status=200):
        request=Request(url,data=json.dumps(data).encode() if data else None,headers={'Content-Type':'application/json'})
        try:
            response=urlopen(request,timeout=10)
        except HTTPError as error:
            response=error
        with response:
            assert response.status==status
            return response.read()

    browser=root/'browser'
    subprocess.run(base+['--home',str(browser),'cluster','new','auth-proof','--local'],capture_output=True,check=True,timeout=30)
    preserved={p.relative_to(browser):hashlib.sha256(p.read_bytes()).hexdigest() for p in browser.rglob('*') if p.is_file()}
    assert cli(browser,'status',code=3)['status']=='signed_out'
    native=subprocess.Popen(base+['--home',str(browser),'auth','login','--no-browser','--service',args.service],
        env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(native.stderr,selectors.EVENT_READ)
            startup=''
            until=time.monotonic()+20
            url=None
            while not url:
                assert time.monotonic()<until and native.poll() is None,'browser startup failed'
                if selector.select(.1):
                    startup+=os.read(native.stderr.fileno(),8192).decode()
                    url=next((line.strip() for line in startup.splitlines() if line.startswith('http://')),None)
        params=parse_qs(urlparse(url).query,keep_blank_values=True)
        assert params['scope']==[''] and params['code_challenge_method']==['S256']
        code=json.loads(http(args.github_origin+'/fixture/code',{'challenge':params['code_challenge'][0]}))['code']
        callback=params['redirect_uri'][0]
        http(callback+'?'+urlencode({'code':code,'state':'wrong'}),status=400)
        http(callback+'?'+urlencode({'code':code,'state':params['state'][0]}))
        out,err=native.communicate(timeout=30)
        assert native.returncode==0 and not err
        account=json.loads(out)['account']
    finally:
        if native.poll() is None:
            native.terminate()
            native.wait(timeout=5)
    path=browser/'auth'/'session.json'
    stored=json.loads(path.read_text())
    secrets.append(stored['token'])
    assert path.stat().st_mode & 0o077==0
    assert cli(browser,'status')['account']['account_id']==account['account_id']
    stored.update(phase='pending',session=None)
    path.write_text(json.dumps(stored))
    assert cli(browser,'login')['status']=='active'
    assert json.loads(path.read_text())['phase']=='active'
    assert cli(browser,'logout')['status']=='signed_out' and json.loads(path.read_text()) is None
    assert cli(browser,'status',code=3)['status']=='signed_out'
    assert all(hashlib.sha256((browser/p).read_bytes()).hexdigest()==digest for p,digest in preserved.items()),'authentication changed cluster state or keys'
    device=root/'device'
    assert cli(device,'login','--headless','--service',args.service)['account']['account_id']==account['account_id']
    secrets.append(json.loads((device/'auth'/'session.json').read_text())['token'])
    assert cli(device,'logout')['status']=='signed_out'
    report={'result':'passed','account_id':account['account_id'],'flows':['browser-state-pkce','device','private-credential','pending-login-recovery','logout']}
    (root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: native browser callback/PKCE, device sign-in, private credentials, recovery and logout',flush=True)


if __name__=='__main__':
    main()
