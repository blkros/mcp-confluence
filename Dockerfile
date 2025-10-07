FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /app/app
COPY .env /app/.env

EXPOSE 9000
# FastMCP는 내부적으로 Uvicorn을 띄워 /mcp 엔드포인트 제공
CMD ["python", "-m", "app.main"]