from io import BytesIO

from PIL import Image


def image_preview(data: bytes) -> Image.Image:
    try:
        with Image.open(BytesIO(data), formats=("PPM", "JPEG")) as image:
            if image.width * image.height > 16_000_000:
                raise ValueError("Изображение должно содержать не более 16 млн пикселей.")
            image.draft("RGB", (420, 260))
            image.thumbnail((420, 260), Image.Resampling.LANCZOS)
            return image.convert("RGB")
    except (OSError, Image.DecompressionBombError, SyntaxError) as error:
        raise ValueError("Не удалось открыть изображение PPM или JPEG.") from error
