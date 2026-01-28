"""
Refactoring Patterns - Shared Utilities

Documented patterns from Phase 8 (CLI Complexity + Patterns) for consistent code organization.

These patterns were applied across 200+ functions during Phase 8 refactoring:
- 79 function length violations fixed
- 99 nesting depth violations addressed
- 200+ helper functions extracted
"""

# Pattern 1: Phase-based extraction
"""
PATTERN: Extract long functions into phase-based helpers

BEFORE:
async def run_loop(self):
    # 146 lines of mixed concerns
    ...

AFTER:
async def run_loop(self):
    await self._phase_1_reconnaissance()
    await self._phase_2_analysis()
    await self._phase_3_reporting()

async def _phase_1_reconnaissance(self):
    # Focused reconnaissance logic

async def _phase_2_analysis(self):
    # Focused analysis logic

async def _phase_3_reporting(self):
    # Focused reporting logic

BENEFITS:
- Clear workflow visibility
- Each phase independently testable
- Easier debugging with meaningful stack traces
"""

# Pattern 2: Guard clauses for nesting reduction
"""
PATTERN: Convert nested conditionals to early returns

BEFORE (nesting depth 4):
def process(self, data):
    if data:
        if data.valid:
            if data.ready:
                return process_data(data)

AFTER (nesting depth 1):
def process(self, data):
    if not data:
        return None
    if not data.valid:
        return None
    if not data.ready:
        return None
    return process_data(data)

BENEFITS:
- Reduced cognitive load
- Clear preconditions
- Easier to understand control flow
"""

# Pattern 3: Helper extraction with _private naming
"""
PATTERN: Extract helpers with _private prefix

CONVENTION:
- Public API: no underscore prefix
- Internal helpers: _private prefix
- Descriptive names: _verb_noun format

EXAMPLES:
- _prepare_validation_context()
- _execute_browser_validation()
- _evaluate_validation_results()
- _handle_validation_error()

BENEFITS:
- Clear API surface
- Prevents accidental external usage
- Self-documenting helper purpose
"""

# Pattern 4: Template string exceptions
"""
PATTERN: Accept template strings >50 lines

EXCEPTION: HTML/JavaScript template strings can exceed 50 lines

RATIONALE:
- Large template literals are naturally long
- Splitting reduces readability
- Not logic complexity, just content

EXAMPLES:
- _build_html_template() - 122 lines (acceptable)
- _build_sink_monitoring() - 113 lines JS template (acceptable)

DECISION SOURCE: 08-03, 08-05
"""

# Pattern 5: Extract validation into boolean helpers
"""
PATTERN: Complex boolean conditions → helper methods

BEFORE:
if ctx and ctx.valid and ctx.ready and not ctx.error:
    ...

AFTER:
def _is_valid_context(self, ctx):
    return ctx and ctx.valid and ctx.ready and not ctx.error

if self._is_valid_context(ctx):
    ...

BENEFITS:
- Reusable validation logic
- Named boolean expressions (self-documenting)
- Testable in isolation
"""

__all__ = []  # Documentation module only - no exports needed
