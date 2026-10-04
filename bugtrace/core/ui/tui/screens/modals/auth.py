"""Configure target authentication without putting credentials in command history."""
import asyncio
from copy import deepcopy

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Collapsible, Input, Select, Static

from ...auth_config import auth_mode, build_auth_options, load_login_yaml


YAML_TEMPLATE = """authentication:
  login_url: "/login"
  login_type: form
  credentials:
    username: "user@example.com"
    password: "your-password"
    # totp_secret: "YOUR_BASE32_SECRET"
  login_flow:
    - "Type $username into the email field"
    - "Type $password into the password field"
    - "Click the 'Sign In' button"
    # - "Enter $totp in the code field"
  success_condition:
    type: url_contains
    value: "/dashboard"""


class AuthModal(ModalScreen[dict | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, options, yaml_path="", **kwargs):
        super().__init__(**kwargs)
        self.options = deepcopy(options)
        self.yaml_path = yaml_path
        self.mode = auth_mode(options)
        self._loading = False

    def compose(self) -> ComposeResult:
        choices = [("None · scan without supplied credentials", "none"),
                   ("Bearer token · Authorization header", "bearer"),
                   ("Login YAML · WEB-compatible login and TOTP", "yaml")]
        if self.mode == "current":
            choices.append(("Keep current scan authentication", "current"))
        headers = self.options.get("custom_headers") or {}
        authorization = next((v for k, v in headers.items() if k.lower() == "authorization"), "")
        token = authorization[7:] if authorization.lower().startswith("bearer ") else ""
        with Vertical(id="auth-container"):
            with VerticalScroll(id="auth-scroll"):
                yield Static("TARGET AUTHENTICATION", id="auth-title")
                yield Static("Credentials for the website you scan. Configure the LLM API key in Provider.", classes="help-text")
                yield Select(choices, value=self.mode, allow_blank=False, compact=True, id="auth-method")
                yield Static(id="auth-method-hint", classes="help-text")
                with Vertical(id="auth-token-fields"):
                    yield Static("BEARER TOKEN", classes="section-header")
                    yield Input(value=token, password=True, placeholder="Paste token or Bearer <token>", compact=True, id="auth-token")
                    yield Static("Sent as Authorization: Bearer <token> to the scan engine.", classes="help-text")
                with Vertical(id="auth-yaml-fields"):
                    yield Static("LOGIN CONFIGURATION", classes="section-header")
                    yield Input(value=self.yaml_path, placeholder="/path/to/auth-config.yaml", compact=True, id="auth-yaml-path")
                    if self.options.get("auth_data") and not self.yaml_path:
                        yield Static("Login already loaded from the CLI · leave the path blank to keep it.", classes="help-text")
                    yield Static("Use the same YAML as the WEB, including optional TOTP/2FA. Apply loads and validates the file.", classes="help-text")
                    with Collapsible(title="YAML template", collapsed=True):
                        yield Static(YAML_TEMPLATE, markup=False, id="auth-template")
                yield Static("Session only · credentials are kept in memory until you close the TUI.\nSwitching methods replaces supplied Authorization, Cookie and login settings; other custom headers are kept.", classes="help-text")
                yield Static(id="auth-error", markup=False, classes="help-text")
            with Horizontal(classes="modal-buttons"):
                yield Button("Apply", id="auth-apply", compact=True, variant="success")
                yield Button("Cancel · Esc", id="auth-cancel", compact=True)

    def on_mount(self):
        self.refresh_method()

    def refresh_method(self):
        self.query_one("#auth-token-fields").display = self.mode == "bearer"
        self.query_one("#auth-yaml-fields").display = self.mode == "yaml"
        self.query_one("#auth-error", Static).update("")
        self.query_one("#auth-method-hint", Static).update({
            "none": "No supplied token or login. The engine can still discover authentication during the scan.",
            "bearer": "Paste an existing access token. Its value stays hidden in this dialog.",
            "yaml": "Log in before scanning and capture the authenticated browser session.",
            "current": "Authentication supplied by the CLI is kept, including combined login and custom headers.",
        }[self.mode])

    def on_select_changed(self, event: Select.Changed):
        if event.select.id == "auth-method" and event.value != Select.NULL:
            self.mode = event.value
            self.refresh_method()

    def action_cancel(self):
        self.dismiss(None)

    async def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "auth-cancel":
            self.action_cancel()
        elif event.button.id == "auth-apply" and not self._loading:
            self._loading = True
            self.query_one("#auth-apply", Button).disabled = True
            self.query_one("#auth-method", Select).disabled = True
            try:
                login = self.options.get("auth_data")
                path = self.query_one("#auth-yaml-path", Input).value.strip()
                if self.mode == "yaml" and path:
                    login, path = await asyncio.to_thread(load_login_yaml, path)
                result = build_auth_options(self.options, self.mode,
                                            token=self.query_one("#auth-token", Input).value, login=login)
            except ValueError as error:
                if self.is_mounted:
                    error_widget = self.query_one("#auth-error", Static)
                    error_widget.update(str(error))
                    error_widget.scroll_visible()
            else:
                if self.is_mounted:
                    self.dismiss({**result, "yaml_path": path if self.mode == "yaml" else self.yaml_path if self.mode == "current" else ""})
            finally:
                self._loading = False
                if self.is_mounted:
                    self.query_one("#auth-apply", Button).disabled = False
                    self.query_one("#auth-method", Select).disabled = False
