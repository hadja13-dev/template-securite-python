"""Analyse structurelle des binaires PE/ELF avec lief."""

import logging

import lief

logger = logging.getLogger(__name__)
lief.logging.disable()


def get_overlay(data: bytes) -> bytes:
    binary = lief.parse(data)
    if binary is None:
        logger.info("Format non reconnu par lief, analyse du fichier entier")
        return data
    overlay = bytes(binary.overlay)
    if not overlay:
        logger.info("Pas d'overlay, analyse du fichier entier")
        return data
    logger.info("Overlay de %d octets détecté", len(overlay))
    return overlay
