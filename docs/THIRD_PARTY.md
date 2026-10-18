# Source, corpus, and demonstration notices

PayProof source is distributed under the [MIT license](../LICENSE), whose
copyright and permission text remain unchanged. The bundled synthetic training
corpus declares CC0-1.0 in `payproof/local_ai_training91.json`.

The project declares `cryptography==50.0.2` for native identity modules. That
dependency is offered under either Apache-2.0 or BSD; retain the applicable notices
from its actual distribution if distributing it. It is not vendored into this
repository or installed by the source fixture instructions. The build backend
declares `setuptools>=65`; its lower bound is not a locked release environment.

The private demonstration used an already installed Ubuntu FFmpeg 6.1.1 toolchain
and Flite's generic English `kal` voice. Audio was synthesized locally; it is not
a recording or clone of a person. No music was added. FFmpeg and Flite binaries
are not bundled in the repository or required to run the application.

Flite includes Carnegie Mellon University material under a permissive license
allowing use and redistribution with preservation of applicable notices. The
production environment's actual Flite copyright notice was inspected during
private assembly. Preserve those applicable notices with any redistributed
software or source; this short attribution does not replace their license text.
Do not imply that Carnegie Mellon University endorses this prototype.

PayPal is referenced to describe the Sandbox integration and the competition.
No ownership of PayPal branding, endorsement, or additional sponsor integration
is claimed. Third-party material remains subject to its original rights.

Upstream version-specific [cryptography license](https://github.com/pyca/cryptography/blob/50.0.2/LICENSE)
is the source for that dual-license statement. The applicable
[Flite notices](licenses/FLITE-NOTICE.txt) are retained here for the generic voice
toolchain attribution; these documents distribute no speech engine binary.
