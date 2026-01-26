"""
Documentation Accuracy Tests (TASK-143)

Verifies that documentation matches actual code behavior.
These tests help catch documentation drift and version mismatches.
"""

import pytest
import re
from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent
AI_CONTEXT_DIR = PROJECT_ROOT / ".ai-context"
BUGTRACE_DIR = PROJECT_ROOT / "bugtrace"


class TestVersionConsistency:
    """Verify version numbers are consistent across code and docs."""

    def test_code_version_exists(self):
        """Verify version is defined in config."""
        from bugtrace.core.config import settings
        assert hasattr(settings, 'VERSION')
        assert settings.VERSION is not None

    def test_version_format(self):
        """Verify version follows semver format."""
        from bugtrace.core.config import settings
        pattern = r'^\d+\.\d+\.\d+$'
        assert re.match(pattern, settings.VERSION), f"Version '{settings.VERSION}' doesn't match semver"

    def test_version_in_master_doc(self):
        """Verify version is mentioned in master documentation."""
        from bugtrace.core.config import settings
        master_doc = AI_CONTEXT_DIR / "BUGTRACE_MASTER_DOC.md"

        if not master_doc.exists():
            pytest.skip("Master doc not found")

        content = master_doc.read_text()
        assert settings.VERSION in content, f"Version {settings.VERSION} not found in master doc"

    def test_version_in_readme(self):
        """Verify version is mentioned in AI context README."""
        from bugtrace.core.config import settings
        readme = AI_CONTEXT_DIR / "README.md"

        if not readme.exists():
            pytest.skip("README not found")

        content = readme.read_text()
        assert settings.VERSION in content, f"Version {settings.VERSION} not found in README"


class TestReactorVersion:
    """Verify Reactor version documentation matches code."""

    def test_reactor_docstring_mentions_v4(self):
        """Verify Reactor docstring says V4."""
        reactor_file = BUGTRACE_DIR / "core" / "reactor.py"

        if not reactor_file.exists():
            pytest.skip("Reactor file not found")

        content = reactor_file.read_text()
        # Check docstring contains V4
        assert "V4" in content, "Reactor should mention V4 in docstring"

    def test_no_v5_in_reactor(self):
        """Verify Reactor doesn't claim to be V5."""
        reactor_file = BUGTRACE_DIR / "core" / "reactor.py"

        if not reactor_file.exists():
            pytest.skip("Reactor file not found")

        content = reactor_file.read_text()
        # V5 should not appear in active code (comments about migration are OK)
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if 'V5' in line and not line.strip().startswith('#'):
                # Allow in strings that reference documentation
                if 'doc' not in line.lower() and 'migration' not in line.lower():
                    pytest.fail(f"Line {i+1} contains V5 reference in non-comment: {line}")

    def test_docs_say_v4_not_v5(self):
        """Verify main docs reference V4, not V5."""
        master_doc = AI_CONTEXT_DIR / "BUGTRACE_MASTER_DOC.md"

        if not master_doc.exists():
            pytest.skip("Master doc not found")

        content = master_doc.read_text()
        # Should have V4 references
        assert "V4" in content or "Reactor V4" in content, "Master doc should mention V4"
        # Title should not say V5
        first_lines = '\n'.join(content.split('\n')[:10])
        assert "V5" not in first_lines, "Title/header should not reference V5"


class TestVisionModelDocs:
    """Verify vision model documentation is accurate."""

    def test_vision_model_config_exists(self):
        """Verify VALIDATION_VISION_MODEL setting exists."""
        from bugtrace.core.config import settings
        # Check if vision model setting exists
        assert hasattr(settings, 'VALIDATION_VISION_MODEL') or hasattr(settings, 'VISION_MODEL'), \
            "Vision model config should exist"

    def test_vision_model_documented(self):
        """Verify vision model is documented in README."""
        readme = AI_CONTEXT_DIR / "README.md"

        if not readme.exists():
            pytest.skip("README not found")

        content = readme.read_text()
        # Should mention qwen or vision model configuration
        has_qwen = "qwen" in content.lower()
        has_vision_config = "VALIDATION_VISION_MODEL" in content

        assert has_qwen or has_vision_config, "Vision model should be documented"


class TestPhaseNaming:
    """Verify phase naming is consistent."""

    def test_phases_doc_exists(self):
        """Verify phases.md documentation exists."""
        phases_doc = AI_CONTEXT_DIR / "architecture" / "phases.md"
        assert phases_doc.exists(), "phases.md should exist in architecture folder"

    def test_phases_doc_has_all_phases(self):
        """Verify phases.md documents all 4 phases."""
        phases_doc = AI_CONTEXT_DIR / "architecture" / "phases.md"

        if not phases_doc.exists():
            pytest.skip("Phases doc not found")

        content = phases_doc.read_text()

        # Check for phase constants
        assert "PHASE_1" in content, "Should document PHASE_1"
        assert "PHASE_2" in content, "Should document PHASE_2"
        assert "PHASE_3" in content, "Should document PHASE_3"
        assert "PHASE_4" in content, "Should document PHASE_4"

        # Check for friendly names
        assert "Hunter" in content, "Should document Hunter phase"
        assert "Researcher" in content, "Should document Researcher phase"
        assert "Validator" in content, "Should document Validator phase"
        assert "Reporter" in content, "Should document Reporter phase"

    def test_team_uses_documented_phases(self):
        """Verify team.py uses the documented phase constants."""
        team_file = BUGTRACE_DIR / "core" / "team.py"

        if not team_file.exists():
            pytest.skip("Team file not found")

        content = team_file.read_text()

        # These should all appear in team.py
        assert "PHASE_1" in content, "team.py should use PHASE_1"
        assert "PHASE_2" in content, "team.py should use PHASE_2"
        assert "PHASE_3" in content, "team.py should use PHASE_3"
        assert "PHASE_4" in content, "team.py should use PHASE_4"


class TestNoStaleReferences:
    """Check for outdated documentation references."""

    def test_no_v5_in_active_docs(self):
        """Verify active docs don't reference V5 architecture."""
        active_docs = [
            AI_CONTEXT_DIR / "README.md",
            AI_CONTEXT_DIR / "BUGTRACE_MASTER_DOC.md",
            AI_CONTEXT_DIR / "architecture" / "architecture_overview.md",
            AI_CONTEXT_DIR / "architecture" / "architecture_v4.md",
        ]

        for doc_path in active_docs:
            if not doc_path.exists():
                continue

            content = doc_path.read_text()
            # Check title/header doesn't say V5
            lines = content.split('\n')[:20]
            header = '\n'.join(lines)

            # V5 should not be in document titles
            if "# " in header:
                title_lines = [l for l in lines if l.startswith('# ')]
                for title in title_lines:
                    assert "V5" not in title, f"Title in {doc_path.name} should not reference V5"

    def test_no_strix_eater_branding(self):
        """Verify Strix Eater cosmetic naming is removed from active docs."""
        # Architecture doc should not have Strix Eater in title
        arch_doc = AI_CONTEXT_DIR / "architecture" / "architecture_v4.md"

        if not arch_doc.exists():
            pytest.skip("Architecture doc not found")

        content = arch_doc.read_text()
        lines = content.split('\n')[:5]
        title = '\n'.join(lines)

        # Strix Eater might appear as historical note but not in title
        assert "Strix Eater" not in title or "Previously" in title, \
            "Strix Eater should not be in title (historical note OK)"


class TestFilenameConsistency:
    """Check that renamed files don't have stale references."""

    def test_no_reference_to_old_filenames(self):
        """Verify no links to old V5 filenames."""
        readme = AI_CONTEXT_DIR / "README.md"

        if not readme.exists():
            pytest.skip("README not found")

        content = readme.read_text()

        # These old filenames should not be linked
        old_names = [
            "BUGTRACE_V5_MASTER_DOC.md",
            "architecture_v4_strix_eater.md",
            "REPORTING_V5_SPEC.md",
        ]

        for old_name in old_names:
            assert old_name not in content, f"README still references old filename: {old_name}"
