"""The voice worker must import with nothing but the speech dependencies.

The managed voice runtime installs the Servonaut wheel without its
dependencies, plus only the speech closure. Importing the worker — and the
engine modules it builds its services from — must therefore load nothing
outside the standard library, Servonaut itself, and that closure. Each
check runs in a fresh isolated interpreter (``-I``, as the runtime launches
the worker): modules already imported by other tests would hide a leak.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys

import servonaut

SRC_ROOT = Path(servonaut.__file__).resolve().parents[1]
PYPROJECT = SRC_ROOT.parent / "pyproject.toml"

# Import names the speech closure may bring: the voice extras themselves
# and what they pull in (capture, recognition, synthesis, model download).
VOICE_CLOSURE = frozenset({
    "numpy",
    "sounddevice", "_sounddevice", "cffi", "_cffi_backend", "pycparser",
    "sherpa_onnx", "_sherpa_onnx",
    "faster_whisper", "ctranslate2", "onnxruntime", "av", "tokenizers",
    "huggingface_hub", "hf_xet", "tqdm", "yaml", "filelock", "fsspec", "packaging",
    "requests", "urllib3", "certifi", "idna", "charset_normalizer",
    "httpx", "httpcore", "h11", "anyio", "sniffio", "typing_extensions",
})

# The modules the worker imports when it builds its services.
ENGINE_MODULES = (
    "servonaut.services.voice_input_service",
    "servonaut.services.voice_streaming_service",
    "servonaut.services.voice_output_service",
    "servonaut.services.voice_conversation_service",
    "servonaut.services.voice_vad",
)


def _foreign_modules(*imports: str) -> list[str]:
    """Non-stdlib, non-Servonaut top-level modules loaded by *imports*.

    Modules already loaded at interpreter startup are not counted: ``site``
    runs the environment's ``.pth`` hooks (setuptools installs one that
    loads ``_distutils_hack``) before any import under test.
    """
    code = (
        "import json, sys\n"
        "startup = set(sys.modules)\n"
        f"sys.path.insert(0, {str(SRC_ROOT)!r})\n"
        + "".join(f"import {name}\n" for name in imports)
        + "tops = {name.split('.')[0] for name in set(sys.modules) - startup}\n"
        "ignored = set(sys.stdlib_module_names) | {'__main__', 'servonaut'}\n"
        "print(json.dumps(sorted(tops - ignored)))\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _voice_extra_requirements() -> set[str]:
    """Import names of every requirement in the pyproject ``voice*`` extras."""
    text = PYPROJECT.read_text(encoding="utf-8")
    names: set[str] = set()
    for _extra, body in re.findall(r"^(voice[\w-]*)\s*=\s*\[(.*?)\]", text, re.MULTILINE | re.DOTALL):
        for requirement in re.findall(r'"([A-Za-z0-9_.-]+)', body):
            names.add(requirement.lower().replace("-", "_"))
    return names


def test_worker_import_loads_only_the_voice_closure() -> None:
    foreign = _foreign_modules("servonaut.desktop.voice.worker")
    assert set(foreign) <= VOICE_CLOSURE, sorted(set(foreign) - VOICE_CLOSURE)


def test_engine_modules_load_only_the_voice_closure() -> None:
    foreign = _foreign_modules("servonaut.desktop.voice.worker", *ENGINE_MODULES)
    assert set(foreign) <= VOICE_CLOSURE, sorted(set(foreign) - VOICE_CLOSURE)


def test_worker_import_skips_the_parent_side_modules() -> None:
    code = (
        "import json, sys\n"
        f"sys.path.insert(0, {str(SRC_ROOT)!r})\n"
        "import servonaut.desktop.voice.worker\n"
        "print(json.dumps(sorted(name for name in sys.modules if name.startswith('servonaut'))))\n"
    )
    result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60)
    loaded = set(json.loads(result.stdout))
    for parent_side in (
        "servonaut.desktop.voice.connection",
        "servonaut.desktop.voice.service",
        "servonaut.desktop.voice.setup_service",
        "servonaut.desktop.voice.runtime",
        "servonaut.services.voice_setup_service",
    ):
        assert parent_side not in loaded


def test_allowlist_covers_every_voice_extra() -> None:
    extras = _voice_extra_requirements()
    assert {"numpy", "sounddevice", "faster_whisper", "sherpa_onnx"} <= extras
    assert extras <= VOICE_CLOSURE, sorted(extras - VOICE_CLOSURE)


def test_worker_handshakes_in_an_isolated_interpreter() -> None:
    code = (
        "import io, sys\n"
        f"sys.path.insert(0, {str(SRC_ROOT)!r})\n"
        "from servonaut.desktop.voice.protocol import HandshakeRequest, encode_voice_message\n"
        "from servonaut.desktop.voice.worker import VoiceWorker\n"
        "out = io.BytesIO()\n"
        "VoiceWorker(io.BytesIO(encode_voice_message(HandshakeRequest(id='h', client_version='t'))), out).run()\n"
        "assert b'\"ok\":true' in out.getvalue(), out.getvalue()\n"
        "print('ok')\n"
    )
    result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_services_package_resolves_its_public_names_lazily() -> None:
    code = (
        "import sys\n"
        f"sys.path.insert(0, {str(SRC_ROOT)!r})\n"
        "import servonaut.services as services\n"
        "assert 'servonaut.services.aws_service' not in sys.modules\n"
        "assert 'TerminalService' in dir(services)\n"
        "from servonaut.services import TerminalService, KeywordStoreInterface\n"
        "from servonaut.services import voice_engines\n"
        "import servonaut.utils as utils\n"
        "assert 'servonaut.utils.formatting' not in sys.modules\n"
        "from servonaut.utils import format_file_size, get_os\n"
        "for module in (services, utils):\n"
        "    try:\n"
        "        module.NoSuchName\n"
        "    except AttributeError:\n"
        "        pass\n"
        "    else:\n"
        "        raise SystemExit('unknown name resolved')\n"
        "print('ok')\n"
    )
    result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_every_public_name_still_resolves() -> None:
    import servonaut.desktop.voice as voice
    import servonaut.services as services
    import servonaut.utils as utils

    for module in (services, utils, voice):
        for name in module.__all__:
            assert getattr(module, name) is not None, (module.__name__, name)
