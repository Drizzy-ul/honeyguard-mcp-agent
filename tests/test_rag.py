"""Tests for RAG retriever (uses ChromaDB EphemeralClient — no network)."""
import pytest

from rag.retriever import TechniqueRetriever


@pytest.fixture(scope="module")
def retriever():
    """Create a TechniqueRetriever instance (loads embedding model once)."""
    return TechniqueRetriever()


class TestTechniqueRetriever:
    def test_retrieve_returns_results(self, retriever):
        results = retriever.retrieve("ssh brute force login attempts", top_k=3)
        assert len(results) >= 1

    def test_result_has_required_keys(self, retriever):
        results = retriever.retrieve("port scanning network discovery", top_k=1)
        result = results[0]
        assert "id" in result
        assert "name" in result
        assert "tactic" in result
        assert "distance" in result

    def test_brute_force_matches_T1110(self, retriever):
        results = retriever.retrieve("password brute force credential stuffing", top_k=1)
        # T1110 (Brute Force) should be the top match
        assert results[0]["id"] == "T1110"

    def test_port_scan_matches_discovery(self, retriever):
        results = retriever.retrieve("port scan network service enumeration", top_k=1)
        assert results[0]["tactic"] == "Discovery"

    def test_top_k_limit_respected(self, retriever):
        results = retriever.retrieve("attack", top_k=2)
        assert len(results) <= 2

    def test_distance_is_float(self, retriever):
        results = retriever.retrieve("malware execution command shell", top_k=1)
        assert isinstance(results[0]["distance"], float)
