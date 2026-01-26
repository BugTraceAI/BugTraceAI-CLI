"""
Event Bus Unit Tests
Tests para el sistema de pub/sub asíncrono.
"""

import pytest
import asyncio
from bugtrace.core.event_bus import EventBus


@pytest.mark.asyncio
async def test_subscribe_and_emit():
    """Test básico de suscripción y emisión"""
    bus = EventBus()
    received = []
    
    async def handler(data):
        received.append(data)
    
    bus.subscribe("test_event", handler)
    await bus.emit("test_event", {"foo": "bar"})
    
    # Esperar a que handler se ejecute (async)
    await asyncio.sleep(0.1)
    
    assert len(received) == 1
    assert received[0]["foo"] == "bar"


@pytest.mark.asyncio
async def test_multiple_subscribers():
    """Test de múltiples suscritos al mismo evento"""
    bus = EventBus()
    received_a = []
    received_b = []
    
    async def handler_a(data):
        received_a.append(data)
    
    async def handler_b(data):
        received_b.append(data)
    
    bus.subscribe("test", handler_a)
    bus.subscribe("test", handler_b)
    
    await bus.emit("test", {"value": 123})
    await asyncio.sleep(0.1)
    
    assert len(received_a) == 1
    assert len(received_b) == 1
    assert received_a[0]["value"] == 123
    assert received_b[0]["value"] == 123


@pytest.mark.asyncio
async def test_handler_error_doesnt_block_others():
    """Test que error en un handler no bloquea otros"""
    bus = EventBus()
    received_good = []
    
    async def handler_bad(data):
        raise Exception("Intentional error")
    
    async def handler_good(data):
        received_good.append(data)
    
    bus.subscribe("test", handler_bad)
    bus.subscribe("test", handler_good)
    
    await bus.emit("test", {"x": 1})
    await asyncio.sleep(0.1)
    
    # Handler good debe ejecutarse aunque bad falle
    assert len(received_good) == 1


@pytest.mark.asyncio
async def test_unsubscribe():
    """Test de desuscripción"""
    bus = EventBus()
    received = []
    
    async def handler(data):
        received.append(data)
    
    bus.subscribe("test", handler)
    result = bus.unsubscribe("test", handler)
    
    assert result is True
    
    await bus.emit("test", {"z": 99})
    await asyncio.sleep(0.1)
    
    # No debe recibir nada (desuscrito)
    assert len(received) == 0


@pytest.mark.asyncio
async def test_unsubscribe_nonexistent():
    """Test desuscribir handler que no existe"""
    bus = EventBus()
    
    async def handler(data):
        pass
    
    result = bus.unsubscribe("test", handler)
    assert result is False


@pytest.mark.asyncio
async def test_stats():
    """Test de estadísticas"""
    bus = EventBus()
    
    async def handler(data):
        pass
    
    bus.subscribe("event_a", handler)
    bus.subscribe("event_b", handler)
    
    await bus.emit("event_a", {})
    await bus.emit("event_a", {})
    await bus.emit("event_b", {})
    
    await asyncio.sleep(0.1)
    
    stats = bus.get_stats()
    
    assert stats["total_events_emitted"] == 3
    assert stats["events_by_type"]["event_a"] == 2
    assert stats["events_by_type"]["event_b"] == 1
    assert stats["total_subscribers"] == 2
    assert stats["subscribers_by_event"]["event_a"] == 1
    assert stats["subscribers_by_event"]["event_b"] == 1


@pytest.mark.asyncio
async def test_non_async_handler_raises():
    """Test que handler no-async genera error"""
    bus = EventBus()
    
    def sync_handler(data):  # Función sync, no async
        pass
    
    with pytest.raises(ValueError, match="must be async function"):
        bus.subscribe("test", sync_handler)


@pytest.mark.asyncio
async def test_reset_stats():
    """Test de reset de estadísticas"""
    bus = EventBus()
    
    async def handler(data):
        pass
    
    bus.subscribe("test", handler)
    await bus.emit("test", {})
    await asyncio.sleep(0.1)
    
    stats_before = bus.get_stats()
    assert stats_before["total_events_emitted"] == 1
    
    bus.reset_stats()
    
    stats_after = bus.get_stats()
    assert stats_after["total_events_emitted"] == 0
    assert len(stats_after["events_by_type"]) == 0


@pytest.mark.asyncio
async def test_event_with_no_subscribers():
    """Test emitir evento sin suscritos no genera error"""
    bus = EventBus()
    
    # No debe generar excepción
    await bus.emit("nonexistent_event", {"data": "test"})
    await asyncio.sleep(0.1)
    
    stats = bus.get_stats()
    assert stats["total_events_emitted"] == 1
    assert stats["events_by_type"]["nonexistent_event"] == 1
