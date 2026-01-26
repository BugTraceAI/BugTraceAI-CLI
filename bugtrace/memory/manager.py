import networkx as nx
import lancedb
import pyarrow as pa
import uuid
import os
import json
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger

logger = get_logger("core.memory")

# Lazy import to avoid startup delays if not used immediately
try:
    from sentence_transformers import SentenceTransformer
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False
    logger.warning("sentence-transformers not installed. Semantic search will be disabled.")

class MemoryManager:
    """
    The Brain of BugtraceAI (Phoenix Edition).
    
    Capabilities:
    1. Knowledge Graph (NetworkX): Tracks structural relationships (URL -> Input -> Vulnerability).
    2. Semantic Memory (LanceDB): Stores embeddings of findings for similarity search.
    3. Persistence: Saves state to disk to survive restarts.
    """
    
    def __init__(self):
        # 1. Initialize Knowledge Graph
        self.graph = nx.MultiDiGraph()
        self.graph_path = settings.LOG_DIR / "knowledge_graph.gml"
        self._load_graph()

        # 2. Initialize Vector DB (LanceDB)
        self.vector_db_path = settings.LOG_DIR / "lancedb"
        self.vector_db_path.mkdir(parents=True, exist_ok=True)
        self.vector_db = lancedb.connect(str(self.vector_db_path))
        
        # 3. Initialize Embedding Model (Lazy Load)
        self.model = None
        if EMBEDDINGS_AVAILABLE:
            try:
                # Lightweight model for local use
                # Set a timeout for the download if possible or handle the error
                import os
                os.environ['HF_HUB_ENABLE_HF_TRANSFER'] = '1' # Optional speedup
                self.model = SentenceTransformer('all-MiniLM-L6-v2') 
                logger.info("Memory: Embedding model loaded (all-MiniLM-L6-v2)")
            except Exception as e:
                logger.warning(f"Failed to load embedding model (likely network timeout): {e}. Running in semantic-blind mode.")
                self.model = None
                # Don't crash, just proceed without embeddings

        # 4. Initialize Tables
        self._init_vector_table()

    def _load_graph(self):
        """Loads the graph from disk if it exists."""
        if self.graph_path.exists():
            try:
                self.graph = nx.read_gml(str(self.graph_path))
                logger.info(f"Memory: Restored Knowledge Graph ({self.graph.number_of_nodes()} nodes).")
            except Exception as e:
                logger.error(f"Failed to load graph: {e}. Starting fresh.")
    
    def _save_graph(self):
        """Persists the graph to disk."""
        try:
            # GML doesn't support None/dict values well sometimes, so we verify data
            # For simplicity in this tool, we assume basic types are used in props
            nx.write_gml(self.graph, str(self.graph_path))
        except Exception as e:
            logger.error(f"Failed to save graph: {e}")

    def _init_vector_table(self):
        """Initializes the LanceDB table with proper schema."""
        # 384 dimensions for all-MiniLM-L6-v2
        dim = 384 
        
        schema = pa.schema([
            pa.field("vector", pa.list_(pa.float32(), dim)),
            pa.field("text", pa.string()),
            pa.field("type", pa.string()),
            pa.field("metadata", pa.string()), # JSON string
            pa.field("timestamp", pa.string())
        ])
        
        try:
            self.obs_table = self.vector_db.create_table(
                "observations", 
                schema=schema, 
                exist_ok=True # Use existing if present
            )
        except Exception as e:
            logger.error(f"Failed to init vector table: {e}")
            try:
                self.obs_table = self.vector_db.open_table("observations")
            except:
                self.obs_table = None

    def _get_embedding(self, text: str) -> List[float]:
        """Generates embedding for text."""
        if not self.model:
            return [0.0] * 384 # Fallback dummy vector
        return self.model.encode(text).tolist()

    def add_node(self, node_type: str, label: str, properties: Dict[str, Any] = {}):
        """
        Adds a node to the Knowledge Graph and Vector Index.
        Atomic operation: Updates both Graph and Vector DB.
        """
        node_id = f"{node_type}:{label}"
        
        # Sanitize properties for GML (keys must be strings, no nested complex objects if possible)
        safe_props = {}
        for k, v in properties.items():
            # Rename conflicting keys
            if k == "type":
                key_name = "element_type"
            elif k == "label":
                key_name = "node_label"
            elif k == "created_at":
                key_name = "original_created_at"
            else:
                key_name = k
                
            if isinstance(v, (str, int, float, bool)):
                safe_props[key_name] = v
            else:
                try:
                    safe_props[key_name] = json.dumps(v)
                except:
                    safe_props[key_name] = str(v)
                    
        # 1. Update Graph
        if not self.graph.has_node(node_id):
            self.graph.add_node(
                node_id, 
                type=node_type, 
                label=label, 
                **safe_props, 
                created_at=datetime.now().isoformat()
            )
            self._save_graph()
        else:
            # Update existing properties
            attrs = {k: v for k, v in safe_props.items()}
            nx.set_node_attributes(self.graph, {node_id: attrs})
            self._save_graph()

        # 2. Update Vector DB (Only for interesting nodes like Findings or Inputs)
        if node_type in ["Finding", "FindingCandidate", "Vulnerability"]:
            description = f"{node_type} {label} {properties.get('details', '')}"
            vector = self._get_embedding(description)
            
            data = [{
                "vector": vector,
                "text": description,
                "type": node_type,
                "metadata": json.dumps(properties),
                "timestamp": datetime.now().isoformat()
            }]
            
            if self.obs_table:
                self.obs_table.add(data) # Append mode by default

    def add_edge(self, source_type: str, source_label: str, target_type: str, target_label: str, relation: str):
        """Adds a relationship edge to the Knowledge Graph."""
        u = f"{source_type}:{source_label}"
        v = f"{target_type}:{target_label}"
        
        # Add nodes if they don't exist (auto-vivification)
        if not self.graph.has_node(u): self.add_node(source_type, source_label)
        if not self.graph.has_node(v): self.add_node(target_type, target_label)
            
        self.graph.add_edge(u, v, relation=relation)
        self._save_graph()

    def store_crawler_findings(self, findings: Dict[str, Any]):
        """Ingest findings from Visual Crawler into the Graph."""
        for url in findings.get("urls", []):
            self.add_node("URL", url)
            
        for inp in findings.get("inputs", []):
            page_url = inp['url']
            detail = inp['details']
            # Improved robust naming
            input_name = detail.get('name') or detail.get('id') or f"input_{uuid.uuid4().hex[:6]}"
            
            # CRITICAL: Inject URL into properties so ExploitAgent can access it
            detail['url'] = page_url
            
            self.add_node("URL", page_url)
            self.add_node("Input", input_name, properties=detail)
            self.add_edge("URL", page_url, "Input", input_name, "HAS_INPUT")
            
        logger.info(f"Memory: Ingested {len(findings.get('inputs', []))} inputs.")

    def get_attack_surface(self, node_type: Optional[str] = "Input") -> List[Dict]:
        """Returns nodes of a specific type (defaults to Input)."""
        surface = []
        for node, data in self.graph.nodes(data=True):
            if node_type:
                if data.get("type") == node_type:
                    surface.append(data)
            else:
                surface.append(data)
        return surface

    def vector_search(self, query: str, limit: int = 5) -> List[Dict]:
        """Performs semantic search on the memory."""
        if not self.obs_table:
            return []
            
        query_vec = self._get_embedding(query)
        try:
            results = self.obs_table.search(query_vec).limit(limit).to_list()
            return results
        except Exception as e:
            logger.error(f"Vector search failed: {e}")
            return []

# Global Memory Singleton
memory_manager = MemoryManager()
