"""
DASTySAST exploitation helpers package.

Holds the exploitation_*.py probe/SQLi/cookie/auth helper modules used by
tests/unit/test_rce_deserialization_validation.py and
tests/unit/test_regression_fixes.py. The live DASTySASTAgent orchestrator
is bugtrace.agents.analysis.agent.DASTySASTAgent, reached in production
via the bugtrace.agents.analysis_agent compatibility facade -- not this
package.
"""
