# Voice

Talk to the AI chat panel instead of typing — and have it talk back. Voice
has three layers, each independently opt-in:

- **Voice input** — press `ctrl+t`, speak, and the transcript lands in the
  chat input box.
- **Spoken replies** — the assistant reads its answers aloud. On the
  hosted-AI path speech starts on the first finished sentence, while the
  rest of the reply is still arriving.
- **Conversation mode** — a hands-free loop: the microphone stays open
  between turns, what you said is sent automatically when you stop
  talking, and the reply is spoken before listening resumes.

All audio processing happens **entirely on your machine**. Speech is
transcribed locally, replies are synthesised locally, and no audio ever
leaves the workstation — the only thing that leaves is the same chat text
that typing the message would have sent to your configured AI provider.

Everything is off by default. The features need a few hundred megabytes of
packages and model weights, so nothing is installed or downloaded until you
ask for it in Settings.

## Installing

Each layer is a pip extra:

```bash
pip install 'servonaut[voice]'            # voice input, batch engine
pip install 'servonaut[voice-streaming]'  # voice input, live text as you speak
pip install 'servonaut[voice-output]'     # spoken replies
```

You do not have to run these yourself: **Settings → AI → Voice Input** has
**Install packages** and **Install speech packages** buttons that detect how
Servonaut was installed (pip or pipx) and run the matching command. For
source checkouts the panel shows the exact command to copy instead.

Voice also needs the PortAudio system library, which pip cannot install:

```bash
sudo apt install libportaudio2     # Debian / Ubuntu
sudo dnf install portaudio         # Fedora
brew install portaudio             # macOS
```

## Setting up in the app

Open **Settings → AI → Voice Input**. The panel reports each requirement
separately and offers the action for whichever one is missing:

| Requirement | How it is satisfied |
|---|---|
| Python packages | The **Install packages** / **Install speech packages** buttons |
| PortAudio library | A system package — the panel shows the command for your distribution |
| Microphone | Any capture device the audio system reports |
| Model weights | A **Download** button per model, which states the size first |

Every download states its size before you press anything:

| Model | Used for | Download |
|---|---|---|
| Whisper `tiny` → `medium` | Voice input (batch engine) | ~75 MB to ~1.5 GB; `small` (~490 MB) is the default |
| Nemotron streaming | Voice input (streaming engine) | ~683 MB |
| Kokoro | Spoken replies | ~126 MB |
| Silero voice detection | Conversation mode and barge-in | under 1 MB |

Model weights live in `~/.servonaut/voice_models/`, except Whisper's, which
land in the Hugging Face cache (`~/.cache/huggingface/hub`, or wherever
`HF_HOME` points).

## Voice input

Turn on **Enable voice input** and save. A microphone button appears in the
chat input row; press it, or `ctrl+t`, to start and stop dictating.

Two engines are available, selected in the panel:

- **Whisper** (default) records first, then transcribes the whole
  utterance. Smaller download and very accurate; the wait is visible on
  longer dictations.
- **Nemotron streaming** decodes as the audio arrives, so words appear in
  the input box while you are still speaking. Larger download, more memory.
  Its **Latency** setting picks the chunk size — smaller shows words sooner
  at a small accuracy cost, and every variant is the same download.

The transcript lands in the input box for you to **review and send**. It is
never sent automatically unless you switch on **Send dictation
automatically**, which is off by default — the assistant can run commands,
and with auto-submit on a misheard word reaches it unedited.

Small speech models fumble hostnames and instance IDs. Servonaut biases the
transcription with the names of the instances currently on screen, which
helps with proper nouns, but `i-0abc123def` will not survive being spoken —
dictate the conversational part and type the identifiers.

## Spoken replies

Turn on **Read replies aloud** under **Spoken replies**, install the speech
packages, and download the speech model (~126 MB). Replies are then read
aloud when they arrive; `ctrl+o` in the chat panel stops the current one.

You can pick a **Voice** (American or British, female or male), a playback
**Speed** (0.5–2.0), and an **Output device** — leave the device blank to
use the system default. Code blocks and tables are not read out character
by character — speech says "Code block shown on screen" or "Table shown on
screen" and the content stays in the panel to read.

With the hosted Servonaut AI provider, speech starts as soon as the first
sentence of the reply has streamed in rather than waiting for the whole
answer. Other providers speak the reply once it is complete.

## Conversation mode

Conversation mode turns the two halves into a hands-free loop. Toggle it
with `ctrl+n` in the chat panel, or switch on **Hands-free conversation on
open** so the loop starts whenever the chat panel opens and everything is
ready. It needs the small voice-detection model on top of the transcription
model (plus the speech model when replies are spoken).

The chat panel shows the loop's state:

| Glyph | State | Meaning |
|---|---|---|
| `◉` | Listening | The microphone is open; stop talking to send what you said |
| `◌` | Thinking | Your turn was sent; the reply is on its way |
| `♪` | Speaking | The reply is being read aloud |

While a reply is being spoken, `Escape` (or `ctrl+n`) interrupts it and
goes straight back to listening. `Escape` does nothing special in the other
states, so it keeps closing dialogs as usual.

Two knobs shape the turn-taking:

- **End a turn after silence** (default 800 ms) — shorter makes the
  assistant answer sooner but clips people who pause mid-sentence.
- **Stop listening after quiet** (default 60 s) — with no speech for this
  long, the loop closes the microphone and stops. Walking away never
  leaves a hot mic behind.

### Barge-in (headphones mode)

By default the microphone is fully closed while the assistant thinks and
speaks — the loop is strictly half-duplex. **Interrupt by speaking** relaxes
that: while a reply is playing, the microphone stays open for voice
detection only, and sustained speech cuts the reply short and returns the
loop to listening, so you can talk over an answer you have already heard
enough of.

Nothing is transcribed during playback — the audio is used only to detect
that you started talking, then discarded. The loop then listens normally
and picks you up from your next words.

**Wear headphones with this switch on.** On speakers the microphone hears
the assistant's own voice, which reads as you barging in — replies
interrupt themselves after a sentence or two. That is why the switch is off
by default and lives behind its own opt-in.

## Privacy

- Dictation, voice detection, and speech synthesis all run locally. No
  audio, and no text derived from audio, is sent to any speech service.
- The only network traffic voice adds is the model downloads you explicitly
  start from Settings.
- What leaves the machine is unchanged by voice: the chat text goes to
  whichever AI provider you configured, exactly as if you had typed it.

## Managing disk space

Each transcription model is several hundred megabytes, and switching engine
or model size leaves the previous download in place. The panel lists every
model on disk with its size, marks which ones are in use, and — when a save
strands one — offers to remove it and shows how much that reclaims. Nothing
is deleted unless you confirm. You can also prune at any time with the
**Remove unused** button, and remove the speech and voice-detection models
individually from their own sections.

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
    "auto_submit": false,
    "tts_enabled": false,
    "tts_voice": "af_heart",
    "tts_speed": 1.0,
    "output_device": null,
    "conversation_mode": false,
    "vad_silence_ms": 800,
    "vad_min_speech_ms": 250,
    "conversation_idle_seconds": 60,
    "barge_in": false
  }
}
```

Set `language` to an ISO 639-1 code, or `"auto"` to let the model detect it
— detection costs an extra pass and misfires on short phrases, so pin the
language when you know it. Leave the device fields as `null` to use the
system defaults. `vad_min_speech_ms` (not in the panel) is how much
sustained speech opens a turn — raise it if coughs or keyboard noise keep
triggering the loop.

## Troubleshooting

**The microphone button is missing.** Voice input is switched off, or the
setup is incomplete. Check Settings → AI → Voice Input.

**The button is greyed out.** Hover it — the tooltip names what is missing.
The usual causes are absent packages, no PortAudio, or an undownloaded
model.

**Settings says ready but the button disagrees.** Press **Re-check**. This
reconciles the two after an install performed outside the app.

**No microphone detected over SSH.** Expected: audio devices are not
forwarded. Voice only works where Servonaut runs locally.

**macOS never prompts for microphone access.** The prompt is issued to the
*terminal emulator*, not to Servonaut. Grant microphone access to your
terminal in System Settings → Privacy & Security → Microphone.

**Replies are silent, or playback errors name the audio output.** Check
that the speech packages and model rows read `OK` in Settings, then check
**Output device** — a blank field uses the system default, and a named
device that has since disappeared (an unplugged headset, say) makes
playback fail until you clear or correct the field. `ctrl+o` also stops
speech; a reply you just silenced is not a broken one.

**Replies keep cutting themselves off in conversation mode.** Barge-in is
on and the microphone is hearing the speakers. Wear headphones, or switch
**Interrupt by speaking** back off.

**Transcription is slow.** Try a smaller Whisper model, or switch to the
streaming engine, which shows text as you speak rather than making you wait
for the whole utterance.

**Short pauses between spoken sentences.** The next sentence is synthesized
while the current one plays, but on CPUs where synthesis runs slower than
the speech itself, a brief pause per sentence boundary remains — the audio
simply isn't ready yet. It shrinks on faster machines and is unrelated to
any setting.
