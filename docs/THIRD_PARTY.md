# Source, corpus, and demonstration notices

PayProof source is distributed under the [MIT license](../LICENSE), whose
copyright and permission text remain unchanged. The bundled synthetic training
corpus declares CC0-1.0 in `payproof/local_ai_training91.json`.

The project declares `cryptography==50.0.2` for native identity modules. That
dependency is offered under either Apache-2.0 or BSD; retain the applicable notices
from its actual distribution if distributing it. It is not vendored into this
repository or installed by the source fixture instructions. The build backend
declares `setuptools>=65`; its lower bound is not a locked release environment.

The final submitted video uses the original application footage and a locally
generated Kokoro v1.0 `af_heart` narration track. It is not a human performance or
a voice clone. No music was added. The upstream
[Kokoro-82M model card](https://huggingface.co/hexgrad/Kokoro-82M) and
[af_heart voice](https://huggingface.co/hexgrad/Kokoro-82M/blob/main/voices/af_heart.pt)
list Apache-2.0. The synthesis engine, ONNX runtime, model and voice weights are
not bundled in this repository and are not required to run the judge application.

The earlier private film used Ubuntu FFmpeg 6.1.1 and Flite's generic `kal` voice.
That former narration was superseded and is not the submitted audio. Preserve
the historical [Flite notices](licenses/FLITE-NOTICE.txt); no FFmpeg or Flite
binary is distributed in this repository. These notices do not imply that the
upstream projects or Carnegie Mellon University endorse PayProof.

PayPal is referenced to describe the Sandbox integration and the competition.
No ownership of PayPal branding, endorsement, or additional sponsor integration
is claimed. Third-party material remains subject to its original rights.

Upstream version-specific [cryptography license](https://github.com/pyca/cryptography/blob/50.0.2/LICENSE)
is the source for that dual-license statement. The applicable
[Flite notices](licenses/FLITE-NOTICE.txt) are retained here for the generic voice
toolchain attribution; these documents distribute no speech engine binary.
