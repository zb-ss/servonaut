ARG APT_UPGRADE_BASE=ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289
FROM ${APT_UPGRADE_BASE}
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
      apt-utils ca-certificates gpg gpg-agent gpgv python3 python3-aiohttp python3-cryptography python3-pytest \
      gir1.2-gtk-3.0 gir1.2-webkit2-4.1 libgirepository-1.0-1 libportaudio2 openssh-client \
      dbus-x11 gcc libc6-dev xauth xvfb && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /repo
ENV PYTHONPATH=/repo:/repo/src
ENV PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python3", "-m", "tests.packaging.apt_upgrade.check_upgrade"]
