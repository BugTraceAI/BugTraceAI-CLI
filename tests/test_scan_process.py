import asyncio
import sys

import pytest

from bugtrace.core.ui.tui.runtime import ScanProcess


@pytest.mark.asyncio
async def test_scan_process_completes_normally():
    """正常完成時，應收到事件與退出碼 0。"""
    script = (
        "import json, sys\n"
        "sys.stdin.readline()\n"
        "print(json.dumps({'event': 'phase', 'phase': 'discovery', "
        "'progress': 0.5}), flush=True)\n"
    )

    scan = ScanProcess(
        target="test.invalid",
        command=[sys.executable, "-u", "-c", script],
    )
    events = []

    result = await asyncio.wait_for(
        scan.run(events.append), timeout=5
    )

    assert result == 0
    assert events == [
        {"event": "phase", "phase": "discovery", "progress": 0.5}
    ]


@pytest.mark.asyncio
async def test_scan_process_handles_failure():
    """子程序異常退出時，應保留非零退出碼。"""
    script = (
        "import sys\n"
        "sys.stdin.readline()\n"
        "sys.exit(7)\n"
    )

    scan = ScanProcess(
        target="test.invalid",
        command=[sys.executable, "-u", "-c", script],
    )

    result = await asyncio.wait_for(
        scan.run(lambda event: None), timeout=5
    )

    assert result == 7


@pytest.mark.asyncio
async def test_scan_process_stops_running_process():
    """執行中的掃描應能在停止要求後結束。"""
    script = (
        "import sys, time\n"
        "sys.stdin.readline()\n"
        "print('READY', flush=True)\n"
        "time.sleep(60)\n"
    )

    scan = ScanProcess(
        target="test.invalid",
        command=[sys.executable, "-u", "-c", script],
    )

    events = []
    task = asyncio.create_task(scan.run(events.append))

    try:
        async def wait_until_ready():
            while not any(
                event.get("message") == "READY"
                for event in events
            ):
                if task.done():
                    raise AssertionError("Scanner exited before READY")
                await asyncio.sleep(0.01)

        await asyncio.wait_for(wait_until_ready(), timeout=5)

        await asyncio.wait_for(
            scan.stop(grace=0.2), timeout=5
        )

        result = await asyncio.wait_for(task, timeout=5)

        assert scan.stop_requested is True
        assert result != 0
        assert scan.process.returncode is not None

    finally:
        if scan.process is not None:
            await asyncio.wait_for(
                scan.stop(grace=0.2), timeout=5
            )
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_scan_process_stop_is_idempotent():
    """Repeated stop calls after completion should be safe."""
    script = (
        "import sys\n"
        "sys.stdin.readline()\n"
    )

    scan = ScanProcess(
        target="test.invalid",
        command=[sys.executable, "-u", "-c", script],
    )

    result = await asyncio.wait_for(
        scan.run(lambda event: None), timeout=5
    )

    assert result == 0

    await asyncio.wait_for(
        asyncio.gather(
            scan.stop(),
            scan.stop(),
            scan.stop(),
        ),
        timeout=5,
    )

    assert scan.stop_requested is True
    assert scan.process.returncode == 0


@pytest.mark.asyncio
async def test_concurrent_stop_while_running():
    """Concurrent stop requests should terminate one running scan safely."""
    script = (
        "import sys, time\n"
        "sys.stdin.readline()\n"
        "print('READY', flush=True)\n"
        "time.sleep(60)\n"
    )

    scan = ScanProcess(
        target="test.invalid",
        command=[sys.executable, "-u", "-c", script],
    )

    events = []
    task = asyncio.create_task(scan.run(events.append))

    try:
        async def wait_until_ready():
            while not any(
                event.get("message") == "READY"
                for event in events
            ):
                if task.done():
                    raise AssertionError("Scanner exited before READY")
                await asyncio.sleep(0.01)

        await asyncio.wait_for(wait_until_ready(), timeout=5)

        await asyncio.wait_for(
            asyncio.gather(
                scan.stop(grace=0.2),
                scan.stop(grace=0.2),
                scan.stop(grace=0.2),
            ),
            timeout=5,
        )

        result = await asyncio.wait_for(task, timeout=5)

        assert scan.stop_requested is True
        assert scan.process.returncode is not None
        assert result != 0

    finally:
        if scan.process is not None:
            await asyncio.wait_for(scan.stop(grace=0.2), timeout=5)
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
