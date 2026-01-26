# Plan de Implementación - HITL + Output Guardrails

**Fecha**: 2026-01-03
**Versión**: v1.3.0
**Estado**: ✅ IMPLEMENTADO

---

## 🎯 OBJETIVO

Implementar 2 mejoras inspiradas en frameworks de seguridad avanzados:
1. **HITL (Human-In-The-Loop)** - Control humano durante el scan
2. **Output Guardrails** - Validación de comandos antes de ejecutar

---

## 📋 MEJORA 1: HITL (Human-In-The-Loop)

### Descripción
Permitir al usuario pausar el scan en cualquier momento (Ctrl+C), ver el estado actual, y decidir si continuar, modificar o abortar.

### Casos de Uso (Bug Bounty)
- Ver qué está encontrando antes de que termine
- Pausar si hay muchos falsos positivos
- Tomar nota de algo interesante y continuar
- Abortar si el target responde raro

### Implementación

**Archivo**: `bugtrace/core/team.py`

```python
class HITLManager:
    """Human-In-The-Loop manager for scan control."""
    
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.paused = False
        
    async def handle_interrupt(self):
        """Called when Ctrl+C is pressed."""
        self.paused = True
        
        print("\n" + "="*60)
        print("⏸️  SCAN PAUSED - Human Control Active")
        print("="*60)
        print(f"Target: {self.orchestrator.target}")
        print(f"Findings so far: {len(self.get_current_findings())}")
        print(f"Active agents: {self.get_active_agents()}")
        print()
        print("Options:")
        print("  [c] Continue scan")
        print("  [f] Show findings so far")
        print("  [s] Save current progress and exit")
        print("  [q] Quit immediately")
        print()
        
        choice = input("Choice: ").strip().lower()
        
        if choice == 'c':
            self.paused = False
            print("▶️  Resuming scan...")
            return "continue"
        elif choice == 'f':
            self.show_findings()
            return await self.handle_interrupt()  # Show menu again
        elif choice == 's':
            await self.save_progress()
            return "save_exit"
        elif choice == 'q':
            return "quit"
        else:
            return await self.handle_interrupt()  # Invalid, show again
```

### Integración

Modificar `TeamOrchestrator.start()`:

```python
def handle_sigint():
    self.sigint_count += 1
    if self.sigint_count >= 2:
        # Force quit
        sys.exit(1)
    else:
        # First Ctrl+C: Enter HITL mode
        asyncio.create_task(self.hitl.handle_interrupt())
```

### Tests
- [ ] Ctrl+C muestra menú
- [ ] 'c' continúa el scan
- [ ] 'f' muestra findings
- [ ] 's' guarda y sale
- [ ] 'q' sale inmediatamente
- [ ] Doble Ctrl+C fuerza salida

---

## 📋 MEJORA 2: Output Guardrails

### Descripción
Validar comandos/payloads antes de ejecutarlos para evitar daños accidentales o fuera de scope.

### Casos de Uso (Bug Bounty)
- No ejecutar comandos destructivos (rm, drop table)
- No escanear fuera del scope
- No enviar payloads que podrían dañar el target
- Detectar si un payload es demasiado agresivo

### Implementación

**Archivo**: `bugtrace/core/guardrails.py` (NUEVO)

```python
class OutputGuardrails:
    """Validate outputs before execution to prevent harm."""
    
    # Dangerous patterns to block
    DANGEROUS_COMMANDS = [
        r"rm\s+-rf",
        r">\s*/dev/",
        r"mkfs\.",
        r"dd\s+if=",
        r":\(\)\{",  # Fork bomb
        r"/dev/tcp",  # Reverse shell
    ]
    
    DANGEROUS_SQL = [
        r"DROP\s+TABLE",
        r"DROP\s+DATABASE",
        r"TRUNCATE\s+TABLE",
        r"DELETE\s+FROM\s+\w+\s*;",  # DELETE without WHERE
    ]
    
    def validate_command(self, command: str) -> tuple[bool, str]:
        """Check if command is safe to execute."""
        for pattern in self.DANGEROUS_COMMANDS:
            if re.search(pattern, command, re.IGNORECASE):
                return False, f"Blocked dangerous command: {pattern}"
        return True, "OK"
    
    def validate_payload(self, payload: str, vuln_type: str) -> tuple[bool, str]:
        """Check if payload is safe for bug bounty."""
        if vuln_type == "SQLi":
            for pattern in self.DANGEROUS_SQL:
                if re.search(pattern, payload, re.IGNORECASE):
                    return False, f"Blocked destructive SQL: {pattern}"
        
        return True, "OK"
    
    def validate_scope(self, url: str, allowed_domains: list) -> tuple[bool, str]:
        """Check if URL is in scope."""
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        
        for allowed in allowed_domains:
            if domain.endswith(allowed):
                return True, "In scope"
        
        return False, f"Out of scope: {domain}"
```

### Integración

En `bugtrace/agents/url_master.py`, antes de ejecutar skills:

```python
from bugtrace.core.guardrails import guardrails

# Before executing any payload
is_safe, reason = guardrails.validate_payload(payload, vuln_type)
if not is_safe:
    logger.warning(f"Guardrail blocked: {reason}")
    return {"success": False, "blocked": reason}
```

### Tests
- [ ] Bloquea `rm -rf`
- [ ] Bloquea `DROP TABLE`
- [ ] Bloquea reverse shells
- [ ] Permite payloads normales de XSS/SQLi
- [ ] Scope checking funciona

---

## 🗓️ PLAN DE EJECUCIÓN

### Fase 1: HITL (30 min)
1. Crear `HITLManager` class
2. Integrar en `TeamOrchestrator`
3. Test manual con Ctrl+C

### Fase 2: Guardrails (20 min)
1. Crear `bugtrace/core/guardrails.py`
2. Integrar en `URLMasterAgent._execute_skill()`
3. Test con payloads peligrosos

### Fase 3: Test Completo (10 min)
1. Ejecutar scan completo
2. Probar Ctrl+C durante scan
3. Verificar que Guardrails no bloquean payloads legítimos

---

## 📁 ARCHIVOS A CREAR/MODIFICAR

| Archivo | Acción | Descripción |
|---------|--------|-------------|
| `bugtrace/core/guardrails.py` | **CREAR** | Output validation |
| `bugtrace/core/team.py` | MODIFICAR | Añadir HITL |
| `bugtrace/agents/url_master.py` | MODIFICAR | Integrar Guardrails |

---

## ✅ CRITERIOS DE ÉXITO

1. Ctrl+C pausa el scan y muestra menú
2. Usuario puede ver findings parciales
3. Usuario puede continuar o abortar
4. Payloads destructivos son bloqueados
5. Payloads legítimos de bug bounty pasan
6. Scan completo funciona igual que antes

---

**Próximo paso**: Implementar Fase 1 (HITL)
