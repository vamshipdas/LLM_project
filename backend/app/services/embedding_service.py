from threading import Lock
from typing import Iterable, List, Union

import numpy as np

from app.config import settings


class EmbeddingService:
    """Thin wrapper over Sentence Transformers.

    The model is loaded lazily on first use so application startup stays fast.
    """

    def __init__(self, model_name: str | None = None):
        self.model_name = model_name or settings.EMBEDDING_MODEL
        self._model = None
        self._load_lock = Lock()

    @property
    def model(self):
        if self._model is None:
            with self._load_lock:
                if self._model is not None:
                    return self._model
                from sentence_transformers import SentenceTransformer

                try:
                    self._model = SentenceTransformer(
                        self.model_name,
                        cache_folder=settings.EMBEDDING_CACHE_DIR,
                        local_files_only=True,
                    )
                except Exception:
                    self._model = SentenceTransformer(
                        self.model_name,
                        cache_folder=settings.EMBEDDING_CACHE_DIR,
                    )
        return self._model

    def warmup(self) -> None:
        """Load the cached model into memory once for this server process."""
        _ = self.model

    @property
    def dimension(self) -> int:
        getter = getattr(self.model, "get_embedding_dimension", None) or getattr(
            self.model, "get_sentence_embedding_dimension", None
        )
        return int(getter())

    def embed(
        self, texts: Union[str, Iterable[str]], normalize: bool = True
    ) -> np.ndarray:
        """Return an (n, dim) float32 matrix of embeddings."""
        if isinstance(texts, str):
            texts = [texts]
        batch: List[str] = list(texts)
        if not batch:
            return np.zeros((0, self.dimension), dtype="float32")
        vectors = self.model.encode(
            batch,
            convert_to_numpy=True,
            normalize_embeddings=normalize,
            show_progress_bar=False,
        )
        return np.asarray(vectors, dtype="float32")

    def embed_query(self, text: str) -> np.ndarray:
        return self.embed(text, normalize=True)[0]


embedding_service = EmbeddingService()
