ARG PYTHON_BASE_IMAGE=docker.m.daocloud.io/library/python:3.12-slim
FROM ${PYTHON_BASE_IMAGE} AS runtime

# PyPI is the reliable default in the supported build environment.  Keep this
# as a build argument so deployments can override it with an internal mirror.
ARG PIP_INDEX_URL=https://pypi.org/simple
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_INDEX_URL=${PIP_INDEX_URL} \
    PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=10

RUN groupadd --system app && useradd --system --gid app --create-home app

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY vendor ./vendor

# Install the package, degrading to a source copy ONLY when the runtime dependencies are
# already present in the image.
#
# Why the fallback exists: `pip install .` needs `setuptools>=69` for PEP 517 build
# isolation.  When PyPI is unreachable the fetch fails, the `RUN` fails, Docker keeps the
# PREVIOUS layer, and `docker compose build api` still reports success from cache - so the
# container served stale code while every "rebuilt and restarted" looked fine.  That
# silent staleness made several rounds of fixes look ineffective.
#
# `vendor/` carries the build backend, so `--no-build-isolation --no-index --find-links
# ./vendor` needs no network at all.  That attempt is preferred because it also resolves
# runtime dependencies from the index when reachable; the fallback covers the fully
# offline case, and it REFUSES to run when a dependency is missing, so a dependency-less
# image can never be produced silently.
RUN set -eux; \
    pip install . --no-build-isolation --no-index --find-links ./vendor --upgrade \
    || pip install . \
    || { \
        echo "pip install unavailable (PyPI unreachable); checking runtime dependencies"; \
        python -c "import docx, fastapi, sqlalchemy, capstone, boto3, pypdf, reportlab, py7zr, temporalio, psycopg, yaml, cryptography; print('runtime dependencies present in image')"; \
        SITE="$(python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"; \
        rm -rf "$SITE/threat_report_agent"; \
        cp -R ./src/threat_report_agent "$SITE/threat_report_agent"; \
        echo "installed threat_report_agent by source copy"; \
    }

# Fail the BUILD, not the runtime, if the installed package is missing or broken.
# Diagnose a suspected stale image with:
#     python .scratch/probe-image-staleness.py   # per-fix LIVE/ABSENT markers
RUN python -c "import importlib; [importlib.import_module(m) for m in ('threat_report_agent', 'threat_report_agent.reporting', 'threat_report_agent.analyst_report', 'threat_report_agent.service', 'threat_report_agent.investigation')]; print('build verification OK')"

USER app
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "threat_report_agent.main:app", "--host", "0.0.0.0", "--port", "8000"]
