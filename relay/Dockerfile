FROM python:3.11-slim
WORKDIR /opt
COPY requirements.txt /opt/requirements.txt
RUN pip install --no-cache-dir -r /opt/requirements.txt
COPY . /opt/relay
ENV PORT=9443
EXPOSE 9443
CMD ["python", "-m", "relay.app"]
