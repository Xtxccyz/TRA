ARG JDK_BASE_IMAGE=docker.m.daocloud.io/library/eclipse-temurin:21-jdk-jammy
ARG PYTHON_BASE_IMAGE=docker.m.daocloud.io/library/python:3.12-slim
FROM ${JDK_BASE_IMAGE} AS jdk

FROM ${PYTHON_BASE_IMAGE}

ARG PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
ENV PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=10 \
    PIP_INDEX_URL=${PIP_INDEX_URL}

ARG GHIDRA_VERSION
ARG GHIDRA_ZIP_URL
ARG GHIDRA_SHA256
ARG DEBIAN_MIRROR

RUN if [ -n "$DEBIAN_MIRROR" ]; then \
        sed -i "s|http://deb.debian.org|${DEBIAN_MIRROR%/}|g" \
            /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; \
    fi \
    && apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*
RUN test -n "$GHIDRA_VERSION" && test -n "$GHIDRA_ZIP_URL" && test -n "$GHIDRA_SHA256"
RUN case "$GHIDRA_ZIP_URL" in \
        https://*) curl --fail --location --proto '=https' --tlsv1.2 --retry 20 --retry-all-errors --retry-delay 2 --continue-at - "$GHIDRA_ZIP_URL" --output /tmp/ghidra.zip ;; \
        http://host.docker.internal:*/*) curl --fail --location --proto '=http' --retry 20 --retry-all-errors --retry-delay 2 --continue-at - "$GHIDRA_ZIP_URL" --output /tmp/ghidra.zip ;; \
        *) echo "Ghidra URL must use HTTPS or the local Docker host" >&2; exit 64 ;; \
    esac \
    && echo "$GHIDRA_SHA256  /tmp/ghidra.zip" | sha256sum --check --strict \
    && ghidra_top_dir="$(unzip -Z1 /tmp/ghidra.zip | awk -F/ 'NF {print $1}' | sort -u)" \
    && test "$(printf '%s\n' "$ghidra_top_dir" | wc -l)" -eq 1 \
    && case "$ghidra_top_dir" in ghidra_${GHIDRA_VERSION}*) ;; *) exit 65 ;; esac \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && test -d "/opt/$ghidra_top_dir" \
    && mv "/opt/$ghidra_top_dir" /opt/ghidra \
    && rm /tmp/ghidra.zip

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/pip python -m pip install .

COPY --from=jdk /opt/java/openjdk /opt/java/openjdk
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"

RUN groupadd --gid 10001 worker \
    && useradd --uid 10001 --gid worker --home-dir /work --no-create-home --shell /usr/sbin/nologin worker
COPY tool-worker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0555 /usr/local/bin/entrypoint.sh

ENV GHIDRA_HOME=/opt/ghidra
ENV HOME=/work
ENV TMPDIR=/work/tmp
ENV JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=/work/tmp"
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
