"""
EmbeddingManager: Generates and manages vector embeddings for findings.

Uses sentence-transformers for semantic similarity search of vulnerabilities.

Author: BugtraceAI-CLI Team
"""
import threading
from typing import List, Dict, Optional
from sentence_transformers import SentenceTransformer
from bugtrace.utils.logger import get_logger

logger = get_logger("core.embeddings")

class MockEmbeddingModel:
    """Fallback model for offline environments."""
    def encode(self, text, convert_to_numpy=True):
        import numpy as np
        # Return random 384-dim vector
        if isinstance(text, list):
            return np.random.rand(len(text), 384)
        return np.random.rand(384)

    def get_sentence_embedding_dimension(self):
        return 384


class EmbeddingManager:
    """Manages vector embeddings for semantic search."""

    _instance: Optional["EmbeddingManager"] = None
    _model: Optional[SentenceTransformer] = None
    _model_lock = threading.Lock()

    def __init__(self, model_name: str = "BAAI/bge-small-en-v1.5"):
        """
        Initialize embedding manager.

        Args:
            model_name: Sentence-transformers model to use
                       'BAAI/bge-small-en-v1.5' is fast and SOTA (384 dimensions)
        """
        self.model_name = model_name
        self._load_model()

    def _load_model(self):
        """Thread-safe lazy load of the embedding model."""
        if self._model is not None:
            return
        with self._model_lock:
            if self._model is not None:
                return
            try:
                logger.info(f"Loading embedding model: {self.model_name}")
                self._model = SentenceTransformer(self.model_name)
                logger.info(f"Model loaded successfully ({self._model.get_sentence_embedding_dimension()}D)")
            except Exception as e:
                logger.error(f"Failed to load embedding model: {e}", exc_info=True)
                logger.warning("Switching to Mock Embedding Model (Offline Mode)")
                self._model = MockEmbeddingModel()
    
    @classmethod
    def get_instance(cls) -> "EmbeddingManager":
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def encode_finding(self, finding: Dict) -> Optional[List[float]]:
        """
        Generate embedding vector for a finding.

        Args:
            finding: Finding dictionary with type, parameter, payload, etc.

        Returns:
            Embedding vector (list of floats), or None if encoding fails
        """
        # Create semantic text representation
        text_parts = []
        
        # Type is most important
        if 'type' in finding:
            text_parts.append(f"Vulnerability type: {finding['type']}")
        
        # Parameter context
        if 'parameter' in finding and finding['parameter']:
            text_parts.append(f"Parameter: {finding['parameter']}")
        
        # Payload (truncated)
        if 'payload' in finding and finding['payload']:
            payload = str(finding['payload'])[:200]  # Limit length
            text_parts.append(f"Payload: {payload}")
        
        # Details/evidence
        if 'details' in finding and finding['details']:
            details = str(finding['details'])[:300]
            text_parts.append(f"Details: {details}")
        
        # URL path (not full URL to avoid bias)
        if 'url' in finding:
            from urllib.parse import urlparse
            parsed = urlparse(finding['url'])
            if parsed.path:
                text_parts.append(f"Path: {parsed.path}")
        
        # Combine into single text
        text = " | ".join(text_parts)
        
        # Generate embedding
        try:
            embedding = self._model.encode(text, convert_to_numpy=True)
            return embedding.tolist()
        except Exception as e:
            logger.error(f"Failed to encode finding: {e}", exc_info=True)
            return None
    
    def encode_query(self, query_text: str) -> Optional[List[float]]:
        """
        Generate embedding for search query.

        Args:
            query_text: Search query (e.g., "SQL injection in id parameter")

        Returns:
            Embedding vector, or None if encoding fails
        """
        try:
            embedding = self._model.encode(query_text, convert_to_numpy=True)
            return embedding.tolist()
        except Exception as e:
            logger.error(f"Failed to encode query: {e}", exc_info=True)
            return None
    
    def batch_encode_findings(self, findings: List[Dict]) -> List[List[float]]:
        """
        Encode multiple findings efficiently.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            List of embedding vectors
        """
        texts = []
        for finding in findings:
            # Create text representation
            text_parts = [
                f"{finding.get('type', 'Unknown')}",
                f"param={finding.get('parameter', 'none')}",
                f"payload={str(finding.get('payload', ''))[:100]}"
            ]
            texts.append(" | ".join(text_parts))
        
        try:
            embeddings = self._model.encode(texts, convert_to_numpy=True)
            return [emb.tolist() for emb in embeddings]
        except Exception as e:
            logger.error(f"Batch encoding failed: {e}", exc_info=True)
            return [None for _ in findings]
    
    def get_embedding_dimension(self) -> int:
        """Get the dimensionality of embeddings."""
        return self._model.get_sentence_embedding_dimension()


# Singleton accessor
def get_embedding_manager() -> EmbeddingManager:
    """Get or create embedding manager instance."""
    return EmbeddingManager.get_instance()
