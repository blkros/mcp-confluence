# C:\Users\nuri\Desktop\mcp-confluence\Dockerfile
FROM python:3.11-slim

# 1) OS deps (tesseract, poppler)
RUN apt-get update && apt-get install -y \
    tesseract-ocr tesseract-ocr-kor tesseract-ocr-eng \
    poppler-utils fonts-nanum fonts-noto-cjk \
 && rm -rf /var/lib/apt/lists/*

ENV TESSDATA_PREFIX=/usr/share/tesseract-ocr/4.00/tessdata

# 2) Python deps
WORKDIR /app
ENV PYTHONUNBUFFERED=1
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
# requirements.txt에 없다면 별도로 설치
RUN pip install --no-cache-dir pytesseract pdf2image pillow

# 3) App code
COPY app/ /app/app
COPY .env /app/.env

# 4) OCR env (이미지 안에서 기본값으로 켜두고, compose로 덮어써도 됨)
ENV OCR_ENABLED=true \
    OCR_LANG=kor+eng \
    OCR_MAX_PAGES=5 \
    OCR_MAX_BYTES=10485760

EXPOSE 9000
CMD ["python", "-m", "app.main"]