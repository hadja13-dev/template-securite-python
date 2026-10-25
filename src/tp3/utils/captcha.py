"""
captcha.py — image preprocessing + OCR.
"""

from __future__ import annotations

import re
from io import BytesIO

from PIL import Image, ImageEnhance, ImageFilter, ImageOps

import pytesseract


def preprocess(image_bytes: bytes) -> Image.Image:
    """Prepare a CAPTCHA image for OCR.

    Pipeline:
      1. Load + convert to grayscale
      2. Auto-contrast
      3. Contrast boost
      4. Light sharpen
      5. Hard threshold (binarisation)
      6. Upscale if the image is small (< 200 px wide)

    Iterate on the threshold / contrast values against the live target
    until OCR becomes reliable.

    Args:
        image_bytes: Raw image data (PNG/JPEG/…).

    Returns:
        Preprocessed ``PIL.Image`` ready for tesseract.
    """
    img = Image.open(BytesIO(image_bytes)).convert("L")

    # Normalise dynamic range
    img = ImageOps.autocontrast(img)

    # Boost contrast
    img = ImageEnhance.Contrast(img).enhance(2.5)

    # Mild sharpen
    img = img.filter(ImageFilter.SHARPEN)

    # Hard binarisation
    threshold = 140
    img = img.point(lambda x: 255 if x > threshold else 0)

    # Upscale small images (helps tesseract)
    w, h = img.size
    if w < 200:
        img = img.resize((w * 2, h * 2), Image.Resampling.LANCZOS)

    return img


def solve_captcha(image_bytes: bytes) -> str:
    """OCR a CAPTCHA image and return the cleaned text.

    Calls ``preprocess`` then ``pytesseract.image_to_string`` with a
    restricted character whitelist.  Non-alphanumeric characters are
    stripped from the result.

    Args:
        image_bytes: Raw CAPTCHA image bytes.

    Returns:
        Cleaned alphanumeric string (may be empty if OCR failed).
    """
    processed = preprocess(image_bytes)
    raw = pytesseract.image_to_string(
        processed,
        config=(
            "--psm 7 "
            "-c tessedit_char_whitelist="
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        ),
    )
    return re.sub(r"[^A-Za-z0-9]", "", raw.strip())
