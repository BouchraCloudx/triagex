# Dockerfile corrigé (étape 3 de la démo TriageX)
# - image de base récente et minimale (Alpine), version figée
# - utilisateur dédié sans privilèges
# - COPY au lieu de ADD
# - serveur de production gunicorn (pas le serveur de développement Flask en mode debug)
# - contrôle de santé intégré
FROM python:3.13-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN addgroup -S app && adduser -S -G app -u 10001 app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

USER 10001
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/ > /dev/null || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:3000", "--workers", "2", "--access-logfile", "-", "app:app"]
