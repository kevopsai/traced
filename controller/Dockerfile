FROM python:3.11-slim
WORKDIR /opt
COPY requirements.txt /opt/requirements.txt
RUN pip install --no-cache-dir -r /opt/requirements.txt
COPY . /opt/controller
ENV PORT=8443
EXPOSE 8443
CMD ["python", "-m", "controller.app"]
