FROM eclipse-temurin:21-jdk-jammy
WORKDIR /var/opt

# Install dependencies + OpenSSH
RUN apt-get update -y && apt-get -y install unzip wget openssh-server

# Setup SSH
RUN mkdir -p /root/.ssh && \
    ssh-keygen -t rsa -b 2048 -f /root/.ssh/id_rsa -N "" && \
    cat /root/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys && \
    chmod 600 /root/.ssh/authorized_keys && \
    chmod 700 /root/.ssh && \
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config && \
    echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config

# Install CrushFTP
COPY CrushFTP.zip .
RUN unzip CrushFTP.zip

EXPOSE 21
EXPOSE 8080
EXPOSE 443
EXPOSE 22

WORKDIR /var/opt/CrushFTP
RUN java -Xmx1024m -jar CrushFTP.jar -a "admin" "admin"

# Start SSH + CrushFTP together
CMD service ssh start && java -Xmx1024m -jar CrushFTP.jar -d
