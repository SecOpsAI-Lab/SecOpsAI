FROM python:3.11-slim

RUN groupadd -r secops && \
    useradd -r -g secops -u 1000 secops

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc libgomp1 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /home/secops/app

COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api/ ./api/

RUN chown -R secops:secops /home/secops/app
USER secops

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
