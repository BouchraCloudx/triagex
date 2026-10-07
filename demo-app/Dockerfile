FROM python:3.8-slim
WORKDIR /app
ADD requirements.txt .
RUN pip install -r requirements.txt
ADD app.py .
EXPOSE 3000
CMD ["python", "app.py"]
