FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --only-binary :all: cryptography && pip install -r requirements.txt

COPY app.py .

EXPOSE 3000

CMD ["python", "-u", "app.py"]
