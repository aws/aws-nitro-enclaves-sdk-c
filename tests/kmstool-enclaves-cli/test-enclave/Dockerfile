FROM amazonlinux:2023

# Install socat for transferring AWS credential during testing
RUN yum install -y socat

# Install jq to parse AWS credential from payload received from parent instance
RUN yum install -y jq

WORKDIR /app

COPY test.sh ./
COPY kmstool_enclave_cli ./
COPY libnsm.so ./

RUN chmod +x test.sh

CMD ["/app/test.sh"]
