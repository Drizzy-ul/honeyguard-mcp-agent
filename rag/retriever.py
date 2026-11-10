"""RAG retrieval wrapper over the MITRE ATT&CK ChromaDB collection."""
from __future__ import annotations

from rag.embedder import MitreEmbedder


class TechniqueRetriever:
    """Retrieves MITRE ATT&CK techniques by semantic similarity.

    Uses an embedded ChromaDB collection (MitreEmbedder) to perform
    cosine-similarity search over technique descriptions.

    Attributes:
        embedder: MitreEmbedder instance with populated ChromaDB collection.
    """

    def __init__(self) -> None:
        self.embedder = MitreEmbedder()

    def retrieve(self, query: str, top_k: int = 3) -> list[dict]:
        """Retrieve top-k MITRE techniques matching the query.

        Args:
            query: Natural-language description of the observed behaviour.
            top_k: Number of top results to return.

        Returns:
            List of dicts, each with keys: id, name, tactic, description,
            distance (lower = more similar).
        """
        results = self.embedder.collection.query(
            query_texts=[query],
            n_results=min(top_k, len(self.embedder.collection.get()["ids"])),
        )
        output = []
        for i, doc_id in enumerate(results["ids"][0]):
            meta = results["metadatas"][0][i]
            output.append({
                "id": doc_id,
                "name": meta["name"],
                "tactic": meta["tactic"],
                "description": results["documents"][0][i],
                "distance": results["distances"][0][i],
            })
        return output
