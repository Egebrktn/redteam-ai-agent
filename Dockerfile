FROM python:3.12-slim

WORKDIR /app

# Bağımlılıkları önce kopyala (cache için)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Proje dosyalarını kopyala
COPY . .

# Ajanı başlat
CMD ["python", "main.py"]