# IDORAgent (Insecure Direct Object Reference)

> **Fase**: 4 (Exploitation)
> **Rol**: Control de Acceso
> **Clase**: `bugtrace.agents.idor_agent.IDORAgent`

## Descripción
Es uno de los agentes más complejos porque requiere "entender" el contexto de autorización.

## Método
- Identifica Identificadores (IDs numéricos, UUIDs).
- Intenta acceder a recursos de otros usuarios (Cross-User).
- Intenta operaciones privilegiadas con usuarios de bajo nivel (Privilege Escalation).

---

## Referencias

- **Skills System**: [SKILLS_SYSTEM.md](../SKILLS_SYSTEM.md) | Skill: `bugtrace/agents/skills/vulnerabilities/idor.md`

---

*Última actualización: 2026-02-02*
*Versión: 2.0.0 (Phoenix Edition)*
