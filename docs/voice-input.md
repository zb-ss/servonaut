# Voice Input

Dictate into the AI chat panel instead of typing. Speech is transcribed
**entirely on your machine** — audio never leaves the workstation and no
transcription service is contacted.

The feature is off by default. It needs a few hundred megabytes of packages
and model weights, so nothing is installed or downloaded until you ask for
it in Settings.

## Enabling it

Open **Settings → AI → Voice Input**. The panel reports each requirement
separately and offers the action for whichever one is missing:

| Requirement | How it is satisfied |
|---|---|
| Python packages | The **Install packages** button, or the command it shows for source installs |
| PortAudio library | A system package — the panel shows the command for your distribution |
| Microphone | Any capture device the audio system reports |
| Model weights | The **Download model** button, which states the size first |

Turn on **Enable voice input**, press Save, then work down the card. When
every row reads `OK`, a microphone button appears in the chat input row.

PortAudio cannot be installed by pip because it is a system library, so that
one row always hands you a command to run yourself:

```bash
sudo apt install libportaudio2     # Debian / Ubuntu
sudo dnf install portaudio         # Fedora
brew install portaudio             # macOS
```

## Choosing an engine

Two engines are available, selected in the panel.

### Whisper (default)

Records first, then transcribes the whole utterance. Smaller download,
very accurate, and the wait is visible on longer dictations — a spinner
runs on the microphone button while the model decodes.

```bash
pip install 'servonaut[voice]'
```

Model sizes range from `tiny` (~75 MB) to `medium` (~1.5 GB); `small`
(~490 MB) is the default and the best balance for dictation.

### Nemotron streaming

Decodes as the audio arrives, so words appear in the input box while you
are still speaking, and already-shown words are never rewritten. Costs a
larger download (~683 MB) and more memory while running.

```bash
pip install 'servonaut[voice-streaming]'
```

The **Latency** setting picks the chunk size (80–1120 ms). Smaller values
show words sooner at a small accuracy cost; every variant is the same
download size, so the choice is free. 320 ms is a good default.

## Using it

Press the microphone button, or `ctrl+t` while the chat input is focused.
Press again to stop.

The transcript lands in the input box for you to **review and send**. It is
never sent automatically unless you switch on **Send dictation
automatically**, which is off by default — the assistant can run commands,
and with auto-submit on a misheard word reaches it unedited.

Recordings are capped (60 seconds by default) so a control left on cannot
fill memory. If a dictation hits the cap you are told that the tail was
dropped rather than left to notice a truncated sentence.

### Accuracy with server names

Small speech models fumble hostnames and instance IDs. Servonaut biases the
transcription with the names of the instances currently on screen, which
helps with proper nouns, but `i-0abc123def` will not survive being spoken.
Dictate the conversational part of a question and type the identifiers.

## Managing disk space

Each model is several hundred megabytes, and switching engine or model size
leaves the previous download in place. The panel lists every model on disk
with its size and marks which one is in use.

When you switch, it offers to remove what is no longer needed and shows how
much that would reclaim. Nothing is deleted unless you confirm — keeping
both is reasonable if you switch back and forth. You can also prune at any
time with the **Remove unused** button.

Streaming model weights live in `~/.servonaut/voice_models/`. Whisper
weights are managed by its own downloader and land in the Hugging Face
cache (`~/.cache/huggingface/hub`, or wherever `HF_HOME` points).

## Configuration

The panel writes to the `voice` section of `~/.servonaut/config.json`:

```json
{
  "voice": {
    "enabled": false,
    "engine": "whisper",
    "model_size": "small",
    "nemotron_latency_ms": 320,
    "language": "en",
    "input_device": null,
    "max_recording_seconds": 60,
    "auto_submit": false
  }
}
```

Set `language` to an ISO 639-1 code, or `"auto"` to let the model detect it
— detection costs an extra pass and misfires on short phrases, so pin the
language when you know it. Leave `input_device` as `null` to use the system
default; set it to a device name only when the default picks the wrong
microphone.

## Troubleshooting

**The microphone button is missing.** Voice input is switched off, or the
setup is incomplete. Check Settings → AI → Voice Input.

**The button is greyed out.** Hover it — the tooltip names what is missing.
The usual causes are absent packages, no PortAudio, or an undownloaded
model.

**Settings says ready but the button disagrees.** Press **Re-check**. This
reconciles the two after an install performed outside the app.

**No microphone detected over SSH.** Expected: audio devices are not
forwarded. Voice input only works where Servonaut runs locally.

**macOS never prompts for microphone access.** The prompt is issued to the
*terminal emulator*, not to Servonaut. Grant microphone access to your
terminal in System Settings → Privacy & Security → Microphone.

**Transcription is slow.** Try a smaller Whisper model, or switch to the
streaming engine, which shows text as you speak rather than making you wait
for the whole utterance.
