"""Provider setup for the next scan; secrets never enter command history."""
import os

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Select, Static


from ...provider_config import provider_presets

class ProviderModal(ModalScreen[dict | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, provider, keys, **kwargs):
        super().__init__(**kwargs)
        self.provider = provider
        self.keys = keys
        self.presets = provider_presets()

    def compose(self) -> ComposeResult:
        with Vertical(id="provider-container"):
            with VerticalScroll(id="provider-scroll"):
                yield Static("LLM PROVIDER", id="provider-title")
                yield Static("Provider and API key for the next scan.", classes="help-text")
                yield Select([(p.get("name", key), key) for key, p in self.presets.items()],
                             value=self.provider, allow_blank=False, id="provider-select", compact=True)
                yield Static(id="provider-key-status", classes="help-text")
                yield Static("API key · blank keeps your configured key", classes="help-text")
                yield Input(password=True, placeholder="Enter API key", id="provider-key", compact=True)
                yield Checkbox("Save this key in local .env", value=False, id="provider-save")
                yield Static("Unchecked: use only in this TUI session. Provider selection lasts until you close the TUI.", classes="help-text")
                yield Static(id="provider-error", classes="help-text", markup=False)
                yield Static(id="provider-description", classes="help-text", markup=False)
            with Horizontal(classes="modal-buttons"):
                yield Button("Apply", id="provider-apply", compact=True, variant="success")
                yield Button("Cancel · Esc", id="provider-cancel", compact=True)

    def on_mount(self):
        self.refresh_provider()

    def configured_key(self, provider):
        from bugtrace.core.config import settings
        key_env = self.presets[provider].get("api_key_env", "")
        return self.keys.get(key_env) or os.environ.get(key_env) or getattr(settings, key_env, None)

    def refresh_provider(self):
        preset = self.presets[self.provider]
        description = preset.get("features", {}).get("description", "")
        self.query_one("#provider-description", Static).update(description[:160] + ("…" if len(description) > 160 else ""))
        self.query_one("#provider-key-status", Static).update(
            "Key configured · connection not tested" if self.configured_key(self.provider) else "No API key configured")
        key = self.query_one("#provider-key", Input)
        key.value = ""
        key.placeholder = preset.get("api_key_hint", "Enter API key")
        self.query_one("#provider-error", Static).update("")

    def on_select_changed(self, event: Select.Changed):
        if event.select.id == "provider-select" and event.value in self.presets:
            self.provider = event.value
            self.refresh_provider()

    def action_cancel(self):
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "provider-cancel":
            self.action_cancel()
        elif event.button.id == "provider-apply":
            from bugtrace.core.config import API_KEY_PLACEHOLDERS
            key = self.query_one("#provider-key", Input).value.strip()
            minimum = {"OPENROUTER_API_KEY": 32, "GLM_API_KEY": 20, "ANTHROPIC_API_KEY": 20}.get(
                self.presets[self.provider].get("api_key_env"), 1)
            if key and (len(key) < minimum or key.lower() in API_KEY_PLACEHOLDERS or any(c.isspace() for c in key) or "\0" in key):
                self.query_one("#provider-error", Static).update("Enter a valid key without whitespace.")
                return
            if not key and not self.configured_key(self.provider):
                self.query_one("#provider-error", Static).update("Enter an API key for this provider.")
                return
            if key and self.query_one("#provider-save", Checkbox).value:
                from bugtrace.utils.env_writer import update_env_var
                if not update_env_var(self.presets[self.provider]["api_key_env"], key):
                    self.query_one("#provider-error", Static).update("Could not save .env. Uncheck Save to use the key for this session.")
                    return
            self.dismiss({"provider": self.provider, "key_env": self.presets[self.provider]["api_key_env"], "key": key})
