
import pytest

from bugtrace.core.ui.tui.widgets.pipeline import PipelineStatus, PHASES


@pytest.fixture
def pipeline():
    widget = PipelineStatus(clock=lambda: 100.0)
    widget.reset()
    return widget


def test_initial_state(pipeline):
    assert pipeline.scan_state == "idle"
    assert len(pipeline.stages) == 6
    assert all(
        stage.state == "pending"
        for stage in pipeline.stages.values()
    )


def test_phase_progress(pipeline):
    pipeline.observe_phase("reconnaissance", 0.5, "Running")

    stage = pipeline.stages["reconnaissance"]

    assert stage.state == "running"
    assert stage.progress == 50


def test_phase_completed(pipeline):
    pipeline.observe_phase("reconnaissance", 1.0, "Done")

    stage = pipeline.stages["reconnaissance"]

    assert stage.state == "complete"
    assert stage.progress == 100


def test_scan_failure(pipeline):
    pipeline.observe_phase("reconnaissance", 0.5)
    pipeline.set_scan_state("failed")

    assert pipeline.scan_state == "failed"
    assert pipeline.stages["reconnaissance"].state == "failed"


def test_incomplete_scan_completion(pipeline):
    pipeline.observe_phase("reconnaissance", 1.0)
    pipeline.set_scan_state("complete")

    assert pipeline.stages["reconnaissance"].state == "complete"

    assert pipeline.stages["discovery"].state == "unobserved"

    completed = sum(
        stage.state == "complete"
        for stage in pipeline.stages.values()
    )

    assert completed == 1


def test_running_phase_on_scan_completion(pipeline):
    pipeline.observe_phase("reconnaissance", 0.5)
    pipeline.set_scan_state("complete")

    stage = pipeline.stages["reconnaissance"]

    # Document current implementation behavior.
    assert stage.state == "complete"
    assert stage.progress == 100
