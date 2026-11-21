ARG APT_FIXTURE_BASE=ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289
FROM ${APT_FIXTURE_BASE}
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends apt-utils gpg gpg-agent gpgv python3 python3-cryptography python3-pytest && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /repo
ENV PYTHONPATH=/repo:/repo/src
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["python3", "tests/packaging/apt/check_archive.py"]
