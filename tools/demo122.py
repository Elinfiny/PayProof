"""One private hosted demo production. No ZIP rebuild, provider or model execution."""
import os,sys,json,pathlib,hashlib,subprocess,time,datetime,tempfile,selectors,signal,stat,resource,re,shutil,csv,urllib.parse
root=pathlib.Path.cwd();started=time.monotonic();records=[];stage=None;outcome='NOT_STARTED';first_error=None
LIMIT=32*1024**2;global_deadline=started+500
def stamp():return {'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'monotonic_ns':time.monotonic_ns()}
def digest(b):return hashlib.sha256(b).hexdigest()
def blob(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def emit(x):print(json.dumps(x,sort_keys=True),flush=True)
def disk_bytes():
    return sum(p.stat().st_size for p in stage.rglob('*') if p.is_file() and not p.is_symlink())
def run(name,args,seconds,cwd,env):
    assert seconds>5,'No child launch without execution/reap reserve'
    pre=stamp();s=time.monotonic();deadline=s+seconds;work=deadline-5
    streams={'stdout':bytearray(),'stderr':bytearray()};counts={'stdout':0,'stderr':0};hashes={k:hashlib.sha256() for k in streams}
    sel=selectors.DefaultSelector();proc=None;reason=None;eof=set();cleanup_errors=[];code=None
    def limits():resource.setrlimit(resource.RLIMIT_FSIZE,(512*1024*1024,512*1024*1024))
    def kill():
        try:os.killpg(proc.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        except BaseException as e:cleanup_errors.append(str(e))
    try:
        proc=subprocess.Popen(args,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,preexec_fn=limits)
        for key,pipe in [('stdout',proc.stdout),('stderr',proc.stderr)]:sel.register(pipe,selectors.EVENT_READ,key)
        while sel.get_map() or proc.poll() is None:
            now=time.monotonic()
            if not reason and (now>=work or disk_bytes()>1024**3):reason='TIMEOUT_OR_MONITORED_STAGE_LIMIT';kill()
            if now>=deadline:
                if reason is None:reason='ABSOLUTE_CHILD_DEADLINE'
                kill();break
            for key,_ in sel.select(min(.1,max(0,deadline-now))):
                chunk=os.read(key.fileobj.fileno(),8192)
                if chunk:
                    k=key.data;counts[k]+=len(chunk);hashes[k].update(chunk);remaining=131072-len(streams[k]);streams[k].extend(chunk[:max(0,remaining)])
                    if counts[k]>131072 and reason is None:reason='STREAM_LIMIT_ORIGINAL_PREFIX_RETAINED';kill()
                else:eof.add(key.data);sel.unregister(key.fileobj);key.fileobj.close()
        try:code=proc.wait(timeout=max(.001,deadline-time.monotonic()))
        except subprocess.TimeoutExpired:cleanup_errors.append('REAP_UNKNOWN');kill()
    except BaseException as error:
        if reason is None:reason=type(error).__name__+':'+str(error)
        if proc is not None:kill()
        if proc is not None:
            try:code=proc.wait(timeout=max(.001,deadline-time.monotonic()))
            except subprocess.TimeoutExpired:cleanup_errors.append('REAP_UNKNOWN')
    finally:
        for key in list(sel.get_map().values()):key.fileobj.close()
        sel.close()
    rec={'phase':name,'pre':pre,'post':stamp(),'seconds':time.monotonic()-s,'exit':code,'failure':reason,'cleanup_errors':cleanup_errors,'EOF_both':eof=={'stdout','stderr'},'reaped':proc is not None and proc.poll() is not None}
    for key,data in streams.items():
        rec[key+'_bytes']=counts[key];rec[key+'_sha256']=hashes[key].hexdigest();rec[key+'_retained_bytes']=len(data);rec[key+'_retained_sha256']=digest(data);(stage/(name+'.'+key+'.raw')).write_bytes(data)
    (stage/(name+'.terminal.json')).write_text(json.dumps(rec));records.append(rec)
    emit({'terminal':rec,'stdout':streams['stdout'].decode('utf8','replace'),'stderr':streams['stderr'].decode('utf8','replace')})
    assert code==0 and reason is None and rec['EOF_both'] and rec['reaped'] and not cleanup_errors,name
    return bytes(streams['stdout'])

original_run=run
def run(name,args,seconds,cwd,env):
    return original_run(name,args,min(seconds,global_deadline-time.monotonic()-15),cwd,env)
def filepin(p):
    b=p.read_bytes();return {'name':p.name,'bytes':len(b),'sha256':digest(b)}
def tools_available(env):
    """Prefer existing official distro binaries; install only a fully planned signed Ubuntu closure."""
    found={n:shutil.which(n) for n in ['ffmpeg','ffprobe','espeak-ng','espeak']};details={'before':found,'install_calls':0,'download_cap':128*1024**2,'install_deadline_seconds':180}
    missing=[]
    if not found['ffmpeg'] or not found['ffprobe']:missing.append('ffmpeg')
    if not found['espeak-ng'] and not found['espeak']:missing.append('espeak-ng')
    if missing and global_deadline-time.monotonic()>255:
        try:
            # No apt update/repository/mirror change. Missing signed official indexes is an audio gate.
            apt_deadline=time.monotonic()+180
            signed=[p for p in pathlib.Path('/var/lib/apt/lists').glob('*_InRelease') if p.name.startswith(('archive.ubuntu.com_ubuntu_dists_noble','security.ubuntu.com_ubuntu_dists_noble'))]
            assert signed,'No official signed Ubuntu index exposed; no mirror substitution'
            for i,p in enumerate(signed):run('apt-signature-'+str(i),['gpgv','--keyring','/usr/share/keyrings/ubuntu-archive-keyring.gpg',str(p)],min(10,apt_deadline-time.monotonic()),root,env)
            opts=['-o','Acquire::AllowInsecureRepositories=false','-o','APT::Get::AllowUnauthenticated=false','-o','Acquire::AllowDowngradeToInsecureRepositories=false']
            plan=run('apt-plan',['apt-get',*opts,'--print-uris','--yes','--no-install-recommends','--no-upgrade','install',*missing],min(20,apt_deadline-time.monotonic()),root,env).decode()
            uris=re.findall(r"^'([^']+)' (\S+) (\d+) (\S+)$",plan,re.M);assert uris and sum(int(x[2]) for x in uris)<=128*1024**2
            assert all(urllib.parse.urlsplit(x[0]).hostname in ['archive.ubuntu.com','security.ubuntu.com'] and '/ubuntu/pool/' in urllib.parse.urlsplit(x[0]).path for x in uris),'No third-party/mirror route'
            versions=run('apt-closure',['apt-get',*opts,'--simulate','--no-install-recommends','--no-upgrade','install',*missing],min(15,apt_deadline-time.monotonic()),root,env).decode()
            assert not re.search(r'^Remv |^Inst \S+ \[',versions,re.M),'No general upgrade/removal admitted'
            details.update(plan=uris,closure=versions,planned_download_bytes=sum(int(x[2]) for x in uris),install_calls=1)
            run('apt-install',['sudo','-n','apt-get',*opts,'--yes','--no-install-recommends','--no-upgrade','install',*missing],min(140,apt_deadline-time.monotonic()),root,env)
        except BaseException as e:details['audio_gate']={'type':type(e).__name__,'message':str(e)}
    elif missing:details['audio_gate']={'message':'Insufficient remaining wrapper time for install plus first capture; retain capture priority'}
    found={n:shutil.which(n) for n in found};details['after']=found
    for n,p in found.items():
        if p:
            details[n]={'path':p,'resolved':str(pathlib.Path(p).resolve()),**filepin(pathlib.Path(p).resolve())}
            run(n+'-version',[p,'--version' if n.startswith('espeak') else '-version'],10,root,env)
    return found,details
def main():
    global stage,outcome,first_error
    media=None;public=None;capture=None;facts={'schema':'PAYPROOF_DEMO122_PRODUCTION','nonce':'PAYPROOF-DEMO122-PRIVATE-ONCE','source_product_commit':'9d566eba4a7a1b3d73af3708fb4531d35c55129a','source_product_tree':'6ec6a4e063a211a163675d968f4ec87a4b7685f6','private':True,'submitted':False,'provider_calls':0,'model_fit':0,'external_model_calls':0,'captures':0,'records':records,'narration':{'words':331,'segments':6,'status':'NOT_STARTED'}}
    try:
        assert os.environ['INPUT_INVOCATION']==facts['nonce'] and os.environ['GITHUB_RUN_ATTEMPT']=='1'
        assert subprocess.check_output(['git','rev-parse','HEAD'],text=True,timeout=10).strip()==os.environ['INPUT_HEAD']
        assert os.uname().machine=='x86_64' and 'VERSION_ID="24.04"' in pathlib.Path('/etc/os-release').read_text()
        assert subprocess.check_output(['node','--version'],text=True,timeout=5).strip()=='v22.23.3'
        stage=pathlib.Path(tempfile.mkdtemp(prefix='payproof-demo122-',dir=os.environ['RUNNER_TEMP']));stage.chmod(0o700);public=stage/'private-artifact';public.mkdir(mode=0o700)
        assert os.statvfs(stage).f_bavail*os.statvfs(stage).f_frsize>2*1024**3
        product=stage/'product';product.mkdir(mode=0o700)
        source=root/'qa/demo122/SOURCE84.json';manifest=root/'qa/demo122/MANIFEST.csv'
        assert digest(source.read_bytes())=='3f4dc39061f5684780524affa122a1149f281eca05c96c8444a820b5689d3a20' and digest(manifest.read_bytes())=='b057502ea331a200a764949d09830dda3476e4aedb9a6f8c61c38b7794dcb18c'
        proof=json.loads(source.read_bytes());assert proof['source_commit']==facts['source_product_commit'] and proof['source_tree']==facts['source_product_tree'] and proof['source_pr_url']=='https://github.com/Elinfiny/PayProof/pull/26'
        assert len(proof['payload_pins'])==30
        tracked=subprocess.check_output(['git','ls-tree','-rz','HEAD'],timeout=10);gitpins={}
        for row in tracked.split(b'\0'):
            if row:
                meta,name=row.split(b'\t',1);mode,kind,sha=meta.decode().split();gitpins[name.decode()]=(mode,kind,sha)
        for p in proof['payload_pins']:
            name=p['path'];rel=pathlib.PurePosixPath(name);assert not rel.is_absolute() and '..' not in rel.parts and '\\' not in name
            original=root/name;assert original.is_file() and not original.is_symlink();b=original.read_bytes()
            assert gitpins[name]==('100644','blob',p['git_blob']) and blob(b)==p['git_blob'] and digest(b)==p['sha256'] and len(b)==p['bytes']<=65536
            dest=product/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(b)
        (product/'SOURCE84.json').write_bytes(source.read_bytes());(product/'MANIFEST.csv').write_bytes(manifest.read_bytes());facts['product_stage']='30 exact Git payloads plus unchanged existing121 provenance/manifest; no ZIP rebuild, metadata not authority'
        demo=(product/'docs/demo.md').read_text();speeches=re.findall('“(.*?)”',demo,re.S);assert len(speeches)==6
        words=sum(len(s.split()) for s in speeches);assert words==331
        (stage/'tmp').mkdir(mode=0o700);(stage/'user.npmrc').write_text('');(stage/'global.npmrc').write_text('')
        env={'PATH':os.environ['PATH'],'CI':'true','LANG':'C.UTF-8','TMPDIR':str(stage/'tmp'),'npm_config_cache':str(stage/'npm-cache'),'NPM_CONFIG_USERCONFIG':str(stage/'user.npmrc'),'NPM_CONFIG_GLOBALCONFIG':str(stage/'global.npmrc'),'PLAYWRIGHT_BROWSERS_PATH':str(stage/'browsers'),'PLAYWRIGHT_DOWNLOAD_CONNECTION_TIMEOUT':'30000'}
        lock=root/'qa/package-lock.json';assert digest(lock.read_bytes())=='4c5980b6227cd6d180285ea681b30c271cece60651ce9d7c73f8d3273073832d'
        run('npm-ci',['npm','ci','--ignore-scripts','--no-audit','--no-fund','--fetch-retries=0','--registry=https://registry.npmjs.org'],120,root/'qa',env)
        installed=json.loads((root/'qa/node_modules/.package-lock.json').read_bytes());locked=json.loads(lock.read_bytes())
        for n in ['playwright','playwright-core']:
            expected=locked['packages']['node_modules/'+n];actual=installed['packages']['node_modules/'+n];assert actual['version']==expected['version']=='1.64.1' and actual['integrity']==expected['integrity'] and actual['resolved']==expected['resolved']
        metadata=json.loads((root/'qa/node_modules/playwright-core/browsers.json').read_bytes());chromium=next(x for x in metadata['browsers'] if x['name']=='chromium');assert chromium['revision']=='1248' and chromium['browserVersion']=='156.0.8078.4'
        run('chromium-install',['node','qa/node_modules/playwright/cli.js','install','--no-shell','--no-progress','--no-remove','chromium'],180,root,env)
        executable=stage/'browsers/chromium-1248/chrome-linux64/chrome';assert executable.is_file() and not executable.is_symlink();b=executable.read_bytes();assert len(b)==301186376 and digest(b)=='377a9fc07b495c3b8d0ab8ec1fdfd153641759f9756fea34d8dfce4de82f5025'
        run('chromium-version',[str(executable),'--version'],10,root,env)
        bins,toolproof=tools_available(env);facts['tools']=toolproof
        reportfile=stage/'capture-report.json';media=stage/'capture';facts['captures']=1
        captureenv={**env,'DEMO122_PRODUCT':str(product),'DEMO122_MEDIA':str(media),'DEMO122_REPORT':str(reportfile),'DEMO122_NONCE':facts['nonce'],'DEMO122_EXPECTED_HEAD':os.environ['INPUT_HEAD']}
        try:run('first-capture122',['node','qa/demo122.cjs'],220,root,captureenv)
        finally:
            if reportfile.is_file() and reportfile.stat().st_size<=262144:capture=json.loads(reportfile.read_bytes());facts['capture']=capture
        assert capture and capture['status']=='CAPTURED'
        raw=pathlib.Path(capture['raw_video']['path']);facts['raw_video']=filepin(raw);assert raw.stat().st_size<LIMIT-1048576
        voice=bins['espeak-ng'] or bins['espeak'];ff=bins['ffmpeg'];probe=bins['ffprobe'];output=stage/'PayProof_demo122_private.mp4'
        if ff and probe and voice:
            inputs=[];filters=[];starts=[0,25,55,80,120,145];slots=[25,30,25,40,25,15];audio=[]
            for i,speech in enumerate(speeches):
                text=stage/('narration-'+str(i)+'.txt');text.write_text(' '.join(speech.split())+'\n');wav=stage/('voice-'+str(i)+'.wav')
                run('voice-'+str(i),[voice,'-v','en-us','-s','130','-w',str(wav),'-f',str(text)],10,root,env)
                meta=json.loads(run('voice-probe-'+str(i),[probe,'-v','error','-show_format','-of','json',str(wav)],10,root,env));seconds=float(meta['format']['duration']);speed=max(1,seconds/(slots[i]-1));assert speed<=2
                audio.append({**filepin(wav),'duration':seconds,'atempo':speed});inputs+=['-i',str(wav)];filters.append(f'[{i+1}:a]atempo={speed:.8f},adelay={starts[i]*1000}:all=1[a{i}]')
            filters.append(''.join(f'[a{i}]' for i in range(6))+'amix=inputs=6:normalize=0,apad=whole_dur=160,atrim=duration=160[audio]')
            # Transcode the SAME single capture once. No second scenario/capture.
            run('mux-private-final',[ff,'-nostdin','-n','-loglevel','error','-ss',str(capture['lead_seconds']),'-i',str(raw),*inputs,'-filter_complex',';'.join(filters),'-map','0:v:0','-map','[audio]','-t','160','-c:v','libx264','-preset','veryfast','-pix_fmt','yuv420p','-b:v','650k','-maxrate','850k','-bufsize','1700k','-c:a','aac','-b:a','96k','-movflags','+faststart',str(output)],45,root,env)
            meta=json.loads(run('final-media-probe',[probe,'-v','error','-show_streams','-show_format','-of','json',str(output)],10,root,env));duration=float(meta['format']['duration']);assert 150<=duration<180 and output.stat().st_size<LIMIT-1048576
            assert any(x['codec_type']=='video' and x['width']==1280 and x['height']==720 for x in meta['streams']) and any(x['codec_type']=='audio' for x in meta['streams'])
            shutil.copyfile(output,public/output.name)
            facts['narration'].update(status='GENERATED_OFFLINE_ENGLISH_NO_PERSON_CLONE',audio_sources=audio,license_route='Existing official distribution eSpeak/eSpeakNG, no external API or cloned person');facts['final_video']={**filepin(output),'duration_seconds':duration,'probe':meta};outcome='PRIVATE_VIDEO_WITH_NARRATION_CREATED'
        else:
            facts['narration']['status']='AUDIO_ROUTE_UNAVAILABLE_WITHIN_ADMITTED_BOUNDS';facts['audio_gate']='Missing official available voice/ffmpeg/ffprobe; no unsupported installer/API substituted';output=public/'PayProof_demo122_footage_partial.webm';shutil.copyfile(raw,output);facts['partial_video']=filepin(output);outcome='USEFUL_FOOTAGE_CAPTURED_AUDIO_GATE_NOT_FINAL_FILM'
    except BaseException as e:
        first_error={'type':type(e).__name__,'message':str(e),'at':stamp()};outcome='FAIL_OR_PARTIAL_RETAINED_NO_RETRY'
        if capture and capture.get('raw_video') and public:
            p=pathlib.Path(capture['raw_video']['path'])
            if p.is_file() and p.stat().st_size<LIMIT-1048576:
                target=public/'PayProof_demo122_footage_partial.webm'
                if not target.exists():shutil.copyfile(p,target)
                facts['partial_video']=filepin(target)
    finally:
        facts.update(status=outcome,first_error=first_error,elapsed_seconds=time.monotonic()-started,records=records,stage_bytes=disk_bytes() if stage else 0,ephemeral_cleanup='Provider runner retirement; bounded child process groups reaped, original streams retained privately before guard',HTTP_product_startup='ACTUAL_ONLY_IF_CAPTURE_REPORT_EXISTS',new_paid_usd_authority=0)
        if public:
            if capture: (public/'capture.json').write_text(json.dumps(capture,sort_keys=True)+'\n')
            (public/'production.json').write_text(json.dumps(facts,sort_keys=True)+'\n')
            total=sum(p.stat().st_size for p in public.iterdir() if p.is_file());assert total<=LIMIT-65536
            ready=bool(facts.get('final_video') or facts.get('partial_video'))
            with open(os.environ['GITHUB_OUTPUT'],'a') as f:f.write('video_ready='+str(ready).lower()+'\nartifact_path='+str(public)+'\n')
        emit(facts)
    return 0 if outcome=='PRIVATE_VIDEO_WITH_NARRATION_CREATED' else 1
if __name__=='__main__':sys.exit(main())
