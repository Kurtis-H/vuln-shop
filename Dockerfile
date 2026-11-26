FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

# Run as a non-root user, even in a deliberately vulnerable app.
RUN useradd --create-home shop && chown -R shop /app
USER shop

ENV DB_PATH=/app/vuln_shop.db
EXPOSE 8000
CMD ["uvicorn", "app.run:app", "--host", "0.0.0.0", "--port", "8000"]
