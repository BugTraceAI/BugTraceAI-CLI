
import pytest

from bugtrace.core.ui.tui.app import BugTraceApp


@pytest.mark.asyncio
async def test_idle_tui_quits_with_ctrl_q():
    app = BugTraceApp()

    async with app.run_test() as pilot:
        assert app.scan_state == "idle"

        await pilot.press("ctrl+q")

        assert app._tui_quitting is True
        assert app.return_code == 0



@pytest.mark.asyncio
async def test_running_tui_quits_after_stopping_scan():
    """Quit should stop an active scan before exiting."""
    from unittest.mock import AsyncMock

    app = BugTraceApp()

    async with app.run_test():
        fake_scan = AsyncMock()
        app.scan_process = fake_scan
        app._set_state("running")

        await app.action_quit()

        fake_scan.stop.assert_awaited_once()
        assert app._tui_quitting is True
        assert app.return_code == 0


@pytest.mark.asyncio
async def test_quit_when_scan_stop_raises():
    """A scan stop failure should not prevent TUI exit."""
    from unittest.mock import AsyncMock

    app = BugTraceApp()

    async with app.run_test():
        fake_scan = AsyncMock()
        fake_scan.stop.side_effect = RuntimeError("Simulated stop failure")

        app.scan_process = fake_scan
        app._set_state("running")

        await app.action_quit()

        assert app._tui_quitting is True
        assert app.return_code == 0
