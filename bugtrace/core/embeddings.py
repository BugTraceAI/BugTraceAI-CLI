"""
EmbeddingManager: Generates and manages vector embeddings for findings.

Uses sentence-transformers for semantic similarity search of vulnerabilities.

Author: BugtraceAI-CLI Team
"""
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
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        """
        Initialize embedding manager.
        
        Args:
            model_name: Sentence-transformers model to use
                       'all-MiniLM-L6-v2' is fast and good (384 dimensions)
        """
        self.model_name = model_name
        self._load_model()
    
    def _load_model(self):
        """Lazy load the embedding model."""
        if self._model is None:
            try:
                logger.info(f"Loading embedding model: {self.model_name}")
                self._model = SentenceTransformer(self.model_name)
                logger.info(f"✅ Model loaded successfully ({self._model.get_sentence_embedding_dimension()}D)")
            except Exception as e:
                logger.error(f"Failed to load embedding model: {e}", exc_info=True)
                logger.warning("⚠️ Switching to Mock Embedding Model (Offline Mode)")
                self._model = MockEmbeddingModel()
    
    @classmethod
    def get_instance(cls) -> "EmbeddingManager":
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def encode_finding(self, finding: Dict) -> List[float]:
        """
        Generate embedding vector for a finding.
        
        Args:
            finding: Finding dictionary with type, parameter, payload, etc.
            
        Returns:
            Embedding vector (list of floats)
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
            # Return zero vector as fallback
            return [0.0] * self._model.get_sentence_embedding_dimension()
    
    def encode_query(self, query_text: str) -> List[float]:
        """
        Generate embedding for search query.
        
        Args:
            query_text: Search query (e.g., "SQL injection in id parameter")
            
        Returns:
            Embedding vector
        """
        try:
            embedding = self._model.encode(query_text, convert_to_numpy=True)
            return embedding.tolist()
        except Exception as e:
            logger.error(f"Failed to encode query: {e}", exc_info=True)
            return [0.0] * self._model.get_sentence_embedding_dimension()
    
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
            dim = self._model.get_sentence_embedding_dimension()
            return [[0.0] * dim for _ in findings]
    
    def get_embedding_dimension(self) -> int:
        """Get the dimensionality of embeddings."""
        return self._model.get_sentence_embedding_dimension()


# Singleton accessor
def get_embedding_manager() -> EmbeddingManager:
    """Get or create embedding manager instance."""
    return EmbeddingManager.get_instance()
