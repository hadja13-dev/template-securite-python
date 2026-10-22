import hashlib
import logging
import math
from collections import Counter

import magic

logger = logging.getLogger(__name__)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def detect_file_type(data: bytes) -> str:
    try:
        return magic.from_buffer(data)
    except Exception as exc:  # libmagic absente ou contenu illisible
        logger.warning("Détection du type impossible : %s", exc)
        return "unknown"


def get_file_metadata(data: bytes) -> dict:
    metadata = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "size": len(data),
        "entropy": shannon_entropy(data),
        "file_type": detect_file_type(data),
    }
    logger.debug("Métadonnées : %s", metadata)
    return metadata
