# FROM python:3.9

# ADD log_exporter_custom.py .
# WORKDIR /usr/bin/python2
# # RUN pip install --no-cache-dir -r requirements.txt
# RUN pip install requests beautifulsoup4 lxml

# ENTRYPOINT ["python3 ","./log_exporter_custom.py"]
 

# FROM ubuntu:20.04

# RUN apt-get update -y
# RUN apt-get install -y python3
# RUN apt-get install -y python3-pip

# WORKDIR /app

# RUN pip3 install requests beautifulsoup4 lxml prettytable textwrap3 tqdm kubernetes

# COPY . /app

# ENTRYPOINT [ "python3" ]


# FROM ubuntu:20.04

# RUN apt-get update -y && apt-get upgrade -y
# RUN apt-get install -y python3 python3-pip
# RUN apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release
# RUN echo "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
#     tee /etc/apt/sources.list.d/docker-ce.list > /dev/null
# RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -

# # Install kubectl
# RUN curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl"
# RUN chmod +x kubectl
# RUN mv kubectl /usr/local/bin/

# WORKDIR /app

# COPY requirements.txt .

# RUN pip3 install -r requirements.txt

# COPY . /app

# ENTRYPOINT [ "python3", "main.py" ]

FROM python:3.9

WORKDIR /app

COPY requirements.txt .

RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8080

COPY . .

CMD [ "python3", "./main.py" ]