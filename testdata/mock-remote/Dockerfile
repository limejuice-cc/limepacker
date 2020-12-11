FROM alpine:latest

RUN apk update && \
    apk upgrade && \
    apk add openssh

RUN addgroup limey && adduser limey -G limey -D -s /bin/ash && echo "limey:limey" | chpasswd && \
    mkdir -p /home/limey/.ssh && \
    chmod 0700 /home/limey/.ssh &&  \
    echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILKxzQPjuH7PFOkalppQsX8oGIyVfOtUOWrpPyuKBnT0" >> /home/limey/.ssh/authorized_keys && \
    chmod 0600 /home/limey/.ssh/authorized_keys && \
    chown -R limey:limey /home/limey

RUN ssh-keygen -f /etc/ssh/ssh_host_rsa_key -N '' -t rsa && \
    ssh-keygen -f /etc/ssh/ssh_host_ecdsa_key -N '' -t ecdsa -b 521 && \
    ssh-keygen -f /etc/ssh/ssh_host_ed25519_key -N '' -t ed25519 

EXPOSE 22

CMD [ "/usr/sbin/sshd", "-D", "-e" ]