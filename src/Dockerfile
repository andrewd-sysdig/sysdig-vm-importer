FROM python:3.12-slim

WORKDIR /app

COPY import_sysdig_vulns.py requirements.txt /app/

RUN python3 -m pip install -r requirements.txt
 
USER 1000

ENTRYPOINT ["python3", "import_sysdig_vulns.py"]
