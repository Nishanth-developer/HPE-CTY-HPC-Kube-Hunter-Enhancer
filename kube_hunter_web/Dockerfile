
FROM ubuntu:20.04

RUN apt-get update -y && \
    apt-get install -y python3 python3-pip curl gnupg2 && \
    curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add - && \
    echo "deb https://apt.kubernetes.io/ kubernetes-xenial main" > /etc/apt/sources.list.d/kubernetes.list && \
    apt-get update && \
    apt-get install -y kubectl

WORKDIR /app

RUN pip3 install requests beautifulsoup4 lxml prettytable textwrap3 tqdm Flask kubernetes

COPY . /app
EXPOSE 5000
EXPOSE 8080
ENTRYPOINT [ "python3" ]

