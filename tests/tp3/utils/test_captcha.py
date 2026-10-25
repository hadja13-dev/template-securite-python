"""Unit tests for tp3.captcha."""

from __future__ import annotations

from io import BytesIO
from unittest.mock import patch

from PIL import Image

from tp3.utils.captcha import preprocess, solve_captcha


def _make_png_bytes(color: int = 128, size: tuple[int, int] = (100, 40)) -> bytes:
    """Create a simple grayscale PNG as bytes."""
    img = Image.new("L", size, color=color)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# preprocess
# ---------------------------------------------------------------------------


def test_preprocess_returns_image():
    raw = _make_png_bytes()
    result = preprocess(raw)
    assert isinstance(result, Image.Image)
    assert result.mode == "L"


def test_preprocess_upscales_small_image():
    raw = _make_png_bytes(size=(80, 30))
    result = preprocess(raw)
    # original 80 < 200 → should be doubled
    assert result.size[0] == 160
    assert result.size[1] == 60


def test_preprocess_no_upscale_large_image():
    raw = _make_png_bytes(size=(300, 80))
    result = preprocess(raw)
    assert result.size[0] == 300
    assert result.size[1] == 80


def test_preprocess_is_binary():
    """After thresholding every pixel is either 0 or 255."""
    raw = _make_png_bytes(color=100)
    result = preprocess(raw)
    extrema = result.getextrema()
    assert extrema[0] in (0, 255)
    assert extrema[1] in (0, 255)


# ---------------------------------------------------------------------------
# solve_captcha
# ---------------------------------------------------------------------------


@patch("tp3.utils.captcha.pytesseract.image_to_string")
def test_solve_captcha_strips_noise(mock_ocr):
    mock_ocr.return_value = " Ab12!@# "
    raw = _make_png_bytes()
    assert solve_captcha(raw) == "Ab12"


@patch("tp3.utils.captcha.pytesseract.image_to_string")
def test_solve_captcha_empty_on_failure(mock_ocr):
    mock_ocr.return_value = ""
    raw = _make_png_bytes()
    assert solve_captcha(raw) == ""


@patch("tp3.utils.captcha.pytesseract.image_to_string")
def test_solve_captcha_calls_preprocess(mock_ocr):
    mock_ocr.return_value = "TEST"
    raw = _make_png_bytes()
    result = solve_captcha(raw)
    assert result == "TEST"
    mock_ocr.assert_called_once()
    # first positional arg must be a PIL Image
    called_img = mock_ocr.call_args[0][0]
    assert isinstance(called_img, Image.Image)
