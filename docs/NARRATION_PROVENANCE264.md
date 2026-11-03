# PayProof video264 narration provenance

New English narration uses the previously approved stock Kokoro v1.0 `af_heart` voice, without cloning a person or adding music. Authoring only; no project model changes and no speech-service account.

The ONNX conversion is pinned to https://huggingface.co/onnx-community/Kokoro-82M-v1.0-ONNX/tree/1939ad2a8e416c0acfeecc08a694d14ef25f2231.

- Model SHA-256: `8fbea51ea711f2af382e88c833d9e288c6dc82ce5e98421ea61c058ce21a34cb`.
- Stock voice SHA-256: `d583ccff3cdca2f7fae535cb998ac07e9fcb90f09737b9a41fa2734ec44a8f0b`.

The existing authoring approach and dependency versions are adapted from Elinfiny/HestiaRelay `scripts/render_narration.py`, revision `acb483be217ca8d3fe9fbf0a0c7d392da60690a3`. No HestiaRelay content or footage is included.

Kokoro/ONNX conversion: Apache-2.0; kokoro-onnx and ONNX Runtime: MIT; NumPy: BSD-3-Clause; SoundFile: BSD-3-Clause, libsndfile LGPL-2.1-or-later; phonemizer/eSpeak NG: GPL. FFmpeg/libx264 licenses are build-dependent. DejaVu fonts retain their license. No dependency binary, model or voice embedding is committed or distributed with the app. Existing THIRD_PARTY.md remains applicable.

`docs/narration264.json` is the script. The renderer appends a caption band below actual app footage, preserves its chronological frames, and retains raw recording and receipts. Automated full decoding and timing checks are distinct from actual final playback review and publication.
