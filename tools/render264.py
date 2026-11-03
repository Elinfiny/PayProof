"""Assemble the new actual-app recording with pinned local stock narration."""
import hashlib,json,pathlib,subprocess,re,textwrap,urllib.request,math

root=pathlib.Path.cwd();out=root/'media264';final=out/'deliverables';final.mkdir()
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(args,seconds=180):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=seconds).stdout
def stamp(t,ass=False):
 n=round(t*(100 if ass else 1000));s,f=divmod(n,100 if ass else 1000);m,s=divmod(s,60);h,m=divmod(m,60)
 return f'{h}:{m:02}:{s:02}.{f:02}' if ass else f'{h:02}:{m:02}:{s:02},{f:03}'
capture=json.loads((out/'capture.json').read_text());assert capture['state']=='CAPTURED'
source=out/capture['video']['file'];assert digest(source)==capture['video']['sha256']
script=json.loads((root/'docs/narration264.json').read_text());duration=script['duration_seconds'];assert duration==172
modeldir=out/'model';modeldir.mkdir();revision='1939ad2a8e416c0acfeecc08a694d14ef25f2231'
assets=[('onnx/model.onnx','model.onnx','8fbea51ea711f2af382e88c833d9e288c6dc82ce5e98421ea61c058ce21a34cb',350000000),('voices/af_heart.bin','voice.bin','d583ccff3cdca2f7fae535cb998ac07e9fcb90f09737b9a41fa2734ec44a8f0b',2000000)]
for remote,name,expected,cap in assets:
 p=modeldir/name
 with urllib.request.urlopen(f'https://huggingface.co/onnx-community/Kokoro-82M-v1.0-ONNX/resolve/{revision}/{remote}',timeout=45) as response,p.open('xb') as stream:
  count=0
  while True:
   b=response.read(1024*1024)
   if not b:break
   count+=len(b);assert count<=cap;stream.write(b)
 assert digest(p)==expected,name
import numpy as np
import onnxruntime as rt
import soundfile as sf
from kokoro_onnx import Kokoro
np.savez(modeldir/'voices.npz',af_heart=np.fromfile(modeldir/'voice.bin',dtype='<f4').reshape(-1,1,256))
opts=rt.SessionOptions();opts.intra_op_num_threads=2;opts.inter_op_num_threads=1
engine=Kokoro.from_session(rt.InferenceSession(str(modeldir/'model.onnx'),sess_options=opts,providers=['CPUExecutionProvider']),str(modeldir/'voices.npz'))
rate=24000;mix=np.zeros(duration*rate,dtype=np.float32);cues=[];receipts=[]
for scene in script['scenes']:
 sentences=re.split(r'(?<=[.!?])\s+',scene['text']);clips=[]
 for sentence in sentences:
  audio,sr=engine.create(sentence,voice='af_heart',speed=1.0,lang='en-us');assert sr==rate;clips.append((sentence,audio))
 available=scene['end']-scene['start']-.7
 total=sum(len(a)/rate for _,a in clips)+.22*(len(clips)-1)
 speed=max(1,total/available);assert speed<=1.12,('Rewrite rushed narration',speed,scene)
 # Time-stretch only already-generated audio; never re-record the application.
 offset=scene['start']+.25
 for sentence,audio in clips:
  if speed>1:
   tmp=out/'stretch.wav';target=out/'stretched.wav';sf.write(tmp,audio,rate);run(['ffmpeg','-y','-v','error','-i',str(tmp),'-af',f'atempo={speed}',str(target)],30);audio,sr=sf.read(target)
  begin=round(offset*rate);end=begin+len(audio);assert end<scene['end']*rate
  mix[begin:end]=audio;seconds=len(audio)/rate
  # Short captions use the exact spoken sentence; split proportionally only for readability.
  words=sentence.split();chunks=[];current=[]
  for word in words:
   if len(' '.join(current+[word]))>105 and current:chunks.append(' '.join(current));current=[]
   current.append(word)
  if current:chunks.append(' '.join(current))
  cursor=offset
  for chunk in chunks:
   length=seconds*len(chunk.split())/len(words);cues.append((cursor,cursor+length,chunk));cursor+=length
  receipts.append({'start':offset,'duration':seconds,'text':sentence,'speed':speed});offset+=seconds+.22/speed
assert np.isfinite(mix).all();peak=float(np.max(np.abs(mix)));assert peak>0
if peak>.92:mix*=.92/peak
sf.write(out/'narration.wav',mix,rate,subtype='PCM_16')
srt=[];ass=[]
for i,(a,b,t) in enumerate(cues,1):
 lines=textwrap.wrap(t,64);assert len(lines)<=2
 srt.append(f'{i}\n{stamp(a)} --> {stamp(b)}\n'+ '\n'.join(lines)+'\n')
 ass.append(f'Dialogue: 0,{stamp(a,True)},{stamp(b,True)},Default,,0,0,0,,'+r'\N'.join(lines))
(final/'PayProof_English264.srt').write_text('\n'.join(srt))
(out/'captions.ass').write_text('[Script Info]\nScriptType: v4.00+\nPlayResX:1280\nPlayResY:828\n[V4+ Styles]\nFormat: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding\nStyle: Default,DejaVu Sans,24,&H00FFFFFF,&H00FFFFFF,&H00182737,&H00182737,0,0,0,0,100,100,0,0,1,0,0,2,36,36,24,1\n[Events]\nFormat: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text\n'+'\n'.join(ass)+'\n')
video=final/'PayProof_C244_English264.mp4'
run(['ffmpeg','-nostdin','-n','-v','error','-ss',str(capture['lead_seconds']),'-i',str(source),'-i',str(out/'narration.wav'),'-vf',f'pad=1280:828:0:0:0x182737,ass={out}/captions.ass','-map','0:v:0','-map','1:a:0','-af','loudnorm=I=-16:TP=-1.5:LRA=7','-t',str(duration),'-c:v','libx264','-crf','22','-preset','veryfast','-pix_fmt','yuv420p','-c:a','aac','-b:a','128k','-ar','48000','-movflags','+faststart',str(video)],180)
probe=json.loads(run(['ffprobe','-v','error','-show_streams','-show_format','-of','json',str(video)]));assert 171.9<=float(probe['format']['duration'])<173
assert video.stat().st_size<30*1024**2
run(['ffmpeg','-v','error','-i',str(video),'-f','null','-'],120)
receipt={'state':'RENDERED_FULL_DECODE_PASS_AWAITING_PLAYBACK_REVIEW','video_sha256':digest(video),'bytes':video.stat().st_size,'duration':probe['format']['duration'],'source_capture':capture,'narration':receipts,'model_sha256':assets[0][2],'voice_sha256':assets[1][2],'new_paypal_calls':0,'source_commit':capture['source'],'old_video_preserved':'https://youtu.be/eG6frmPgfKw'}
(final/'render264.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({k:v for k,v in receipt.items() if k not in ['source_capture','narration']}))
