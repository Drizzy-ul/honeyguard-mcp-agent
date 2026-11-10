"""ChromaDB embedder for MITRE ATT&CK technique catalog."""
from __future__ import annotations

import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

from rag.mitre_data import MITRE_TECHNIQUES

COLLECTION_NAME = "mitre_attack_techniques"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"


class MitreEmbedder:
    """Embeds MITRE ATT&CK techniques into a ChromaDB in-memory collection.

    Uses sentence-transformers (all-MiniLM-L6-v2) for local, offline
    embedding — no API key required.

    Attributes:
        client: ChromaDB ephemeral client.
        collection: ChromaDB collection containing embedded techniques.
    """

    def __init__(self) -> None:
        self.client = chromadb.EphemeralClient()
        self._ef = SentenceTransformerEmbeddingFunction(
            model_name=EMBEDDING_MODEL
        )
        self.collection = self.client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=self._ef,
        )
        self._populate()

    def _populate(self) -> None:
        """Embed all MITRE techniques into the ChromaDB collection."""
        existing_ids = set(self.collection.get()["ids"])
        new_techniques = [t for t in MITRE_TECHNIQUES if t["id"] not in existing_ids]
        if not new_techniques:
            return

        self.collection.add(
            ids=[t["id"] for t in new_techniques],
            documents=[
                f"{t['name']}: {t['description']}" for t in new_techniques
            ],
            metadatas=[
                {"tactic": t["tactic"], "name": t["name"], "id": t["id"]}
                for t in new_techniques
            ],
        )
