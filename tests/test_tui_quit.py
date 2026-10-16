
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

