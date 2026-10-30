import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from app.config import settings
from app.services.embedding_service import EmbeddingService


class EmbeddingServiceTest(unittest.TestCase):
    def test_model_is_loaded_once_with_persistent_cache(self):
        model = object()
        constructor = Mock(return_value=model)
        module = SimpleNamespace(SentenceTransformer=constructor)
        service = EmbeddingService("test-model")

        with patch.dict(sys.modules, {"sentence_transformers": module}):
            service.warmup()
            self.assertIs(service.model, model)

        constructor.assert_called_once_with(
            "test-model",
            cache_folder=settings.EMBEDDING_CACHE_DIR,
        )


if __name__ == "__main__":
    unittest.main()
