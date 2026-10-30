import json
import os
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from app.config import settings
from app.services.embedding_service import embedding_service


class VectorStore:
    """FAISS IndexFlatIP on L2-normalized vectors (cosine similarity).

    Persisted to disk but only trusted when its on-disk chunk-id ordering still
    matches the DB; otherwise it is rebuilt (DB is source of truth).
    """

    def __init__(self) -> None:
        self._index = None
        self._chunk_ids: List[str] = []   # parallel to index rows
        self._meta: List[dict] = []        # {chunk_id, sop_id, section, content}
        self._dim: Optional[int] = None

    # ------------------------------------------------------------------ init
    def _ensure_index(self):
        if self._index is None:
            import faiss

            self._dim = embedding_service.dimension
            self._index = faiss.IndexFlatIP(self._dim)

    def _persist(self) -> None:
        import faiss

        if self._index is None:
            return
        os.makedirs(settings.DATA_DIR, exist_ok=True)
        faiss.write_index(self._index, settings.FAISS_INDEX_FILE)
        meta_path = settings.FAISS_INDEX_FILE + ".meta.json"
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump(
                {"chunk_ids": self._chunk_ids, "meta": self._meta}, fh
            )

    def _load(self) -> bool:
        import faiss

        if not os.path.exists(settings.FAISS_INDEX_FILE):
            return False
        try:
            self._index = faiss.read_index(settings.FAISS_INDEX_FILE)
            meta_path = settings.FAISS_INDEX_FILE + ".meta.json"
            with open(meta_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self._chunk_ids = list(data.get("chunk_ids", []))
            self._meta = list(data.get("meta", []))
            self._dim = self._index.d
            return True
        except Exception:
            self._index = None
            self._chunk_ids = []
            self._meta = []
            return False

    def _rebuild(self, chunks: List[Tuple[str, str, str, str]]) -> None:
        """chunks: [(chunk_id, sop_id, section, content), ...]"""
        import faiss

        self._ensure_index()
        self._index.reset()
        self._chunk_ids = []
        self._meta = []

        if not chunks:
            return

        texts = [c[3] for c in chunks]
        vectors = embedding_service.embed(texts, normalize=True)
        self._index.add(vectors)
        for cid, sop_id, section, content in chunks:
            self._chunk_ids.append(cid)
            self._meta.append(
                {"chunk_id": cid, "sop_id": sop_id, "section": section, "content": content}
            )
        self._persist()

    # ------------------------------------------------------------------ API
    def bootstrap(self, chunks: List[Tuple[str, str, str, str]]) -> None:
        """Call at startup. Loads disk index if valid, else rebuilds from DB."""
        loaded = self._load()
        if loaded and len(self._chunk_ids) == len(chunks):
            # Verify ordering matches DB exactly.
            disk_ids = list(self._chunk_ids)
            db_ids = [c[0] for c in chunks]
            if disk_ids == db_ids:
                return  # on-disk index is fresh
        self._rebuild(chunks)

    def add_chunks(self, chunks: List[Tuple[str, str, str, str]]) -> None:
        """Incrementally append new chunks (used while seeding SOPs)."""
        self._ensure_index()
        if not chunks:
            return
        texts = [c[3] for c in chunks]
        vectors = embedding_service.embed(texts, normalize=True)
        self._index.add(vectors)
        for cid, sop_id, section, content in chunks:
            self._chunk_ids.append(cid)
            self._meta.append(
                {"chunk_id": cid, "sop_id": sop_id, "section": section, "content": content}
            )
        self._persist()

    def remove_by_sop_id(self, sop_id: str) -> None:
        if self._index is None:
            return
        keep = [
            (cid, m)
            for cid, m in zip(self._chunk_ids, self._meta)
            if m.get("sop_id") != sop_id
        ]
        self._chunk_ids = [c[0] for c in keep]
        self._meta = [c[1] for c in keep]
        if keep:
            texts = [m["content"] for m in self._meta]
            vectors = embedding_service.embed(texts, normalize=True)
            self._index.reset()
            self._index.add(vectors)
        else:
            self._index.reset()
        self._persist()

    def search(
        self, query: str, top_k: int = 4, threshold: float = 0.0
    ) -> List[Tuple[Any, float]]:
        """Returns [(chunk_meta_dict, score), ...] sorted by score desc."""
        if self._index is None or self._index.ntotal == 0:
            return []
        q = embedding_service.embed_query(query).reshape(1, -1)
        scores, idxs = self._index.search(q, min(top_k, self._index.ntotal))
        results: List[Tuple[Any, float]] = []
        for score, idx in zip(scores[0], idxs[0]):
            if idx == -1:
                continue
            if score < threshold:
                continue
            results.append((self._meta[idx], float(score)))
        return results

    @property
    def size(self) -> int:
        return self._index.ntotal if self._index is not None else 0


vector_store = VectorStore()
