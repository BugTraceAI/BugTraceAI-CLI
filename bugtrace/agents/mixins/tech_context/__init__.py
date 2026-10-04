"""TechContextMixin — context-aware technology stack for specialist agents.

Public import path unchanged:
    from bugtrace.agents.mixins.tech_context import TechContextMixin
"""

from bugtrace.agents.mixins.tech_context.load import TechContextLoadMixin
from bugtrace.agents.mixins.tech_context.xss import TechContextXssMixin
from bugtrace.agents.mixins.tech_context.csti import TechContextCstiMixin
from bugtrace.agents.mixins.tech_context.injection import TechContextInjectionMixin
from bugtrace.agents.mixins.tech_context.access import TechContextAccessMixin
from bugtrace.agents.mixins.tech_context.constants import (
    FRAMEWORK_TO_DB,
    SERVER_TO_LANG,
    TAG_TO_DB,
)

__all__ = [
    "TechContextMixin",
    "FRAMEWORK_TO_DB",
    "SERVER_TO_LANG",
    "TAG_TO_DB",
]


class TechContextMixin(
    TechContextLoadMixin,
    TechContextXssMixin,
    TechContextCstiMixin,
    TechContextInjectionMixin,
    TechContextAccessMixin,
):
    """
    Mixin that provides context-aware technology stack loading for specialist agents.

    Designed to be mixed into BaseAgent subclasses to provide:
    - Technology profile loading from recon data
    - Database/server/language inference
    - Context-aware prompt generation for LLM calls
    """
    pass
