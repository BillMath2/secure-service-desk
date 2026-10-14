# Recorded demonstration

Completed October 14, 2026: [play the 3:58 MP4](../../.lab/demo/secure-service-desk-evidence.mp4) or retain the [original MKV](../../.lab/demo/secure-service-desk-evidence.mkv). Both are local artifacts under ignored `.lab/demo`; copy them before removing that directory. They have not been uploaded or published. The recording is a **saved-evidence walkthrough**, with visible labels and report references throughout.

The [capture inspection](../../reports/phase5/capture/results.json) records hashes, 1920×1080/30 fps H.264 video, AAC audio, full decoding of 7,142 frames, and inspection of all eight segment frames. Duration is 238.08 seconds. Peak audio amplitude is 0.884, below clipping; each segment has non-silent audio. [Source alignment](../../reports/phase5/capture/audio-alignment.json) measures a 40 ms offset against the generated narration. OBS reported zero encoder skips and 15 render skips; maximum slide scheduling lag was 17 ms. These are technical checks, not a claim of human listening approval.

The [final narration](narration-final.txt), [eight-segment storyboard](storyboard.json), [content-free evidence export](../../reports/phase5/demo-evidence.json), and [evaluation report](../phase5-report.md) preserve what the recording says and why. The opening and closing cards state its synthetic scope and pending owner decision.

The requested voice is **female British English**. `scripts/New-DemoNarration.ps1` uses installed Windows speech voices locally. Microsoft Hazel is installed and the initial sample generated successfully: 34.08 seconds, mono, 16 kHz, 16-bit PCM, with a nonzero peak below clipping. This is a technical audio check, not a claim of human listening approval.

```powershell
.\scripts\New-DemoNarration.ps1 -VoiceName 'Microsoft Hazel'
```

The default sample is `.lab/demo/narration-sample.wav`. Use `-InputPath`, `-OutputPath` and `-VoiceName` for the final narration. Existing output is preserved unless `-Force` is explicitly supplied.

## Capture setup

OBS 32.2.2 has a separate **Secure Service Desk** profile and scene collection, prepared at 1920 by 1080, 30 fps, MKV recording. Original OBS settings are backed up under `.lab/demo/obs-backup`; the user's Untitled profile and collection are retained. The demo scene uses only explicit local evidence and narration sources. The authenticated OBS WebSocket API controls recording; its password is read locally and is never included in reports or narration.

The initial 37-second browser-source test had a later texture defect. The final take uses eight inspected PNG image slides and a local audio media source. A separate 20-second static-source test passed before recording. The original MKV is preserved; MP4 was remuxed without re-encoding and decoded for verification. No desktop, microphone or camera source is included.

For another take in this prepared workspace, select the dedicated profile and collection, retain the `Evidence` scene with `Evidence slide` and `UK narration` inputs, and enable the authenticated OBS WebSocket server. Then run from the repository root:

```powershell
node docs/demo/record-demo.mjs --test
node docs/demo/record-demo.mjs
```

The controller checks the profile/collection, refuses to interrupt an active recording, enables only the two intended scene sources, records to `.lab/demo`, and saves timing/statistics evidence. OBS gives each take a timestamped filename. Archive the controller's prior JSON records before a new take; it replaces those status files. The controller uses the prepared `slide-01.png` through `slide-08.png` and `narration-final.wav`; it does not synthesize or render missing assets. The [local asset bundle](../../.lab/demo/secure-service-desk-demo-assets.zip) preserves them for relocation, with root-relative image paths in the storyboard.

For a revised script, regenerate each paragraph with `New-DemoNarration.ps1 -VoiceName 'Microsoft Hazel' -Rate 0.95`, then rebuild the timeline with one second of leading silence and 0.7 seconds after each paragraph. Update the storyboard durations to the measured WAV durations. The [assembly provenance](../../reports/phase5/capture/provenance/build-storyboard.py.txt) and [HTML template](presentation-template.html) preserve the original construction. Render and inspect each slide before capture; avoid using an active browser texture as the final recording source. PyAV 16.0.1 and Pillow 11.3.0 were installed in isolated `.lab/media-tools` for remuxing and inspection, without changing application dependencies.

## Evidence presentation

The recording must label saved-report walkthroughs as such. A report card is evidence from an executed probe, not footage of a human clicking the application. Distinguish real-model read/proposal observations, deterministic fixture policy checks, and forced signed browser/MCP workflows. Never narrate a forced action as something the model independently chose.

Required segments are the cited benign answer; injected entry point and independently denied action; requester disclosure boundary; reviewed standard/sensitive temporary grant; rejected confirmation replay versus idempotent execution retry; effective expiry with delayed cleanup; correlated audit delivery; and the scoped MITRE ATLAS/NIST AI RMF interpretation. Show report paths or correlation IDs alongside results. Do not expose credentials or restricted synthetic bodies merely to illustrate a denial.

The final script and evidence references were assembled after evaluation and framework reconciliation. Owner risk acceptance remains a separate decision; neither generated narration nor a passing security test supplies that acceptance. OBS is left open in its dedicated demo profile with recording stopped; the original profile and scene collection remain available. The authenticated control server remains enabled for reuse. The synthetic service-desk containers were stopped after evidence collection.

Official capture references: [OBS remote control](https://obsproject.com/kb/remote-control-guide), [launch parameters](https://obsproject.com/kb/launch-parameters), and [recording output guidance](https://obsproject.com/kb/standard-recording-output-guide).
