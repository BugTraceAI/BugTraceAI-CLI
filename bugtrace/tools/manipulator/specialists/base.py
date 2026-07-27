from abc import ABC, abstractmethod
from typing import List, AsyncIterator
from ..models import MutableRequest, MutationStrategy

class BaseSpecialist(ABC):
    """
    Base class for all specialist mutation agents.
    """
    
    @abstractmethod
    async def analyze(self, request: MutableRequest) -> bool:
        """
        Determines if this specialist is relevant for the given request.
        """
        pass

    @abstractmethod
    async def generate_mutations(self, request: MutableRequest, strategies: List[MutationStrategy]) -> AsyncIterator[MutableRequest]:
        """
        Generates a sequence of mutated requests based on the strategy.
        """
        yield request # Fallback to original if not implemented
