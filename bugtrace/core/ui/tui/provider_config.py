"""Read the same provider presets used by the web API and scan engine."""
import json


def provider_presets():
    from bugtrace.core.config import settings
    presets = {}
    for path in sorted((settings.BASE_DIR / "bugtrace/data/providers").glob("*.json")):
        preset = json.loads(path.read_text())
        presets[path.stem] = preset
    return presets

