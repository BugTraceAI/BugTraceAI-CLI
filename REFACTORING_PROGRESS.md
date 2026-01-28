# Complexity Reduction Refactoring - Phase 08 Plans 05-07

## Objective
Reduce ALL functions outside agents/ to 50 lines or fewer to improve maintainability.

## Completed Refactorings

### ✅ core/team.py (Commit: 5552805)
- **_build_technical_prompt()**: 60 → 15 lines
  - Extracted `_get_default_technical_prompt()` (45 lines)
- **_build_html_template()**: 122 → 34 lines  
  - Extracted `_get_html_styles()` (34 lines, pure CSS - EXEMPT)
  - Extracted `_get_html_sidebar()` (11 lines)
  - Extracted `_get_html_footer()` (13 lines)

### ✅ core/ui.py (Commit: a054684)
- **__init__()**: 56 → 8 lines
  - Extracted `_init_layout()` (10 lines)
  - Extracted `_init_state()` (18 lines)
  - Extracted `_init_metrics()` (8 lines)
- **_keyboard_loop()**: 60 → 18 lines
  - Extracted `_wait_for_active()` (6 lines)
  - Extracted `_keyboard_loop_non_tty()` (13 lines)
  - Extracted `_keyboard_loop_tty()` (17 lines)
  - Extracted `_handle_key_press()` (7 lines)
- **update_payload_section()**: 87 → 9 lines
  - Extracted `_capture_payload_data()` (13 lines)
  - Extracted `_get_panel_width()` (7 lines)
  - Extracted `_build_status_content()` (9 lines)
  - Extracted `_build_payload_content()` (16 lines)
  - Extracted `_build_payload_table()` (7 lines)

### ✅ core/diagnostics.py (Commit: 1d28975)
- **run_all()**: 86 → 13 lines
  - Extracted `_log_debug_paths()` (5 lines)
  - Extracted `_check_docker()` (8 lines)
  - Extracted `_check_api_key()` (7 lines)
  - Extracted `_check_browser()` (10 lines)
  - Extracted `_check_connectivity()` (12 lines)
  - Extracted `_check_credits()` (17 lines)
  - Extracted `_process_credit_response()` (19 lines)

## Remaining Violations (TO BE COMPLETED)

### api/ (1 file - LOW PRIORITY)
- **routes/reports.py**: 
  - `get_report()`: 75 lines - Can extract validation/content-type logic

### skills/ (10 files - HIGH PRIORITY)
- **injection.py** (3 violations):
  - `XSSSkill.execute()`: 177 lines - Extract browser verification, vision validation
  - `SQLiSkill.execute()`: 146 lines - Extract SQLMap execution, result processing
  - `LFISkill.execute()`: 74 lines - Extract payload testing loop

- **advanced.py** (4 violations):
  - `SSRFSkill.execute()`: 61 lines
  - `IDORSkill.execute()`: 57 lines  
  - `OpenRedirectSkill.execute()`: 53 lines
  - `CSRFSkill.execute()`: 51 lines

- **external_tools.py** (2 violations):
  - `SQLMapSkill.execute()`: 76 lines
  - `NucleiSkill.execute()`: 60 lines

- **infrastructure.py** (1 violation):
  - `PrototypePollutionSkill.execute()`: 54 lines

### tools/ (8 files - MEDIUM PRIORITY)
- **headless/dom_xss_detector.py** (1 - EXEMPT):
  - `_build_sink_monitoring()`: 113 lines - Pure JS template string, NO LOGIC - EXEMPT

- **manipulator/orchestrator.py** (1 violation):
  - `_try_mutation()`: 89 lines - Extract detection logic

- **external.py** (7 violations):
  - `_run_container()`: 88 lines - Extract docker command building
  - `run_sqlmap()`: 74 lines - Extract parsing logic
  - `run_gospider()`: 65 lines - Extract URL filtering
  - `run_go_xss_fuzzer()`: 56 lines - Extract payload file handling
  - `run_go_ssrf_fuzzer()`: 51 lines - Already near limit
  - `run_go_idor_fuzzer()`: 54 lines - Already near limit

## Refactoring Patterns Applied

1. **Extract Method**: Move code blocks into dedicated helper methods
2. **Guard Clauses**: Early returns to reduce nesting
3. **Data Transfer Objects**: Bundle related parameters into dicts
4. **Template Method**: Separate algorithm structure from implementation

## Exemptions

### HTML/JS Template Strings
- `_get_html_styles()`: 34 lines of pure CSS - NO branching logic
- `_build_sink_monitoring()`: 113 lines of pure JS - NO branching logic
- Pure data templates don't count toward complexity

## Benefits Achieved

1. **Improved Testability**: Smaller functions are easier to test in isolation
2. **Better Readability**: Each function has single, clear purpose
3. **Easier Debugging**: Smaller scope reduces cognitive load
4. **Enhanced Maintainability**: Changes localized to specific helpers

## Next Steps

1. Complete skills/ refactoring (highest impact on code quality)
2. Refactor tools/ directory (medium priority)
3. Minor cleanup in api/ (low priority)

## Commit Convention

```bash
git commit -m "refactor(08-0X): reduce complexity in <file>

- Extract <helper_name>() from <parent>() (XX → YY lines)
- Apply guard clauses to reduce nesting
- All functions now ≤50 lines"
```

Generated: 2026-01-28
Phase: 08 (WEB Dead Code + Error Handling)
Plans: 05-07 (Complexity Reduction)
