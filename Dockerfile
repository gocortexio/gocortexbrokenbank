# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Intentionally vulnerable Dockerfile for comprehensive policy coverage
# Tri-server architecture: Python/Gunicorn (port 8888) + Java/Tomcat (port 9999) + React/Next.js (port 7777)
# Using Python 3.11 for PyGremlinBox compatibility + bookworm for OpenJDK 17
FROM python:3.11-bookworm

# Docker policy violations for comprehensive testing

# Running as root user (security risk)
USER root

# Installing packages without version pinning including OpenJDK 17 for Spring4Shell
# Create man directories required by OpenJDK packages on slim images
RUN apt-get update && \
    mkdir -p /usr/share/man/man1 && \
    for i in 1 2 3; do \
        apt-get install -y \
        curl \
        wget \
        git \
        vim \
        sudo \
        ssh \
        telnet \
        netcat-openbsd \
        iputils-ping \
        openjdk-17-jdk \
        maven \
        ant \
        supervisor \
        && break || { if [ "$i" -eq 3 ]; then echo "apt-get install failed after 3 attempts"; exit 1; fi; echo "apt-get install attempt $i failed, retrying in 5s..."; sleep 5; }; \
    done && \
    rm -rf /var/lib/apt/lists/*

# Install Node.js 20 LTS for SpaceATM Terminal (React/Next.js)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Setting weak file permissions
RUN chmod 777 /tmp
RUN chmod 755 /etc/passwd

# Installing Apache Tomcat 8.5.0 (highly vulnerable legacy version)
# CVE-2020-1938 (Ghostcat), CVE-2020-9484 (RCE), CVE-2021-25122, CVE-2023-42795, CVE-2023-45648
RUN cd /opt && \
    wget https://archive.apache.org/dist/tomcat/tomcat-8/v8.5.0/bin/apache-tomcat-8.5.0.tar.gz && \
    tar xzvf apache-tomcat-8.5.0.tar.gz && \
    mv apache-tomcat-8.5.0 tomcat && \
    rm apache-tomcat-8.5.0.tar.gz && \
    chmod +x /opt/tomcat/bin/*.sh

# Configure Tomcat with intentionally weak settings
COPY config/tomcat-users.xml /opt/tomcat/conf/tomcat-users.xml
COPY config/context.xml /opt/tomcat/conf/context.xml
COPY config/manager-context.xml /opt/tomcat/webapps/manager/META-INF/context.xml
COPY config/manager-context.xml /opt/tomcat/webapps/host-manager/META-INF/context.xml
RUN chmod 644 /opt/tomcat/conf/tomcat-users.xml && \
    chmod 644 /opt/tomcat/conf/context.xml && \
    chmod 644 /opt/tomcat/webapps/manager/META-INF/context.xml && \
    chmod 644 /opt/tomcat/webapps/host-manager/META-INF/context.xml

# Exposing application ports (8888 for Flask/Gunicorn, 8080 for Tomcat - mapped to 9999 externally)
# 9464 is the OTel default Prometheus scrape port (poll-based metrics)
EXPOSE 8888 8080 7777 9464

# Adding secrets directly in Dockerfile (bad practice)
ENV SECRET_KEY="hardcoded-secret-12345"
ENV DATABASE_PASSWORD="admin123"
ENV API_TOKEN="sk-1234567890abcdef"
ENV SESSION_SECRET="hardcoded-docker-secret-key"
ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
ENV OPENAI_API_KEY="sk-1234567890abcdefghijklmnopqrstuvwxyz"
ENV DATABASE_URL="sqlite:////app/instance/database.db"

# Running commands that could be cached with secrets
RUN echo "admin:password123" > /tmp/credentials.txt
RUN chmod 644 /tmp/credentials.txt

# Setting working directory
WORKDIR /app

# Copying application code first
COPY . .

# Build SpaceATM Terminal (React/Next.js on port 7777)
WORKDIR /app/react-app
RUN npm install && \
    node scripts/patch-react-server-dom.js && \
    node scripts/patch-csrf-origin-check.js && \
    npm run build

# Installing Python packages with vulnerable/older versions for security testing
RUN pip install --no-cache-dir \
    flask==2.0.1 \
    flask-sqlalchemy==2.5.1 \
    requests==2.25.1 \
    pyjwt==1.7.1 \
    cryptography==39.0.0 \
    pyyaml==6.0 \
    gunicorn==20.1.0 \
    werkzeug==2.0.1 \
    ldap3==2.8.1 \
    pymongo==3.12.0 \
    urllib3==1.26.5 \
    flask-login==0.5.0 \
    email-validator==1.1.3 \
    jinja2==3.0.1 \
    pillow==8.1.0 \
    sqlalchemy==1.4.23 \
    faker==18.13.0 \
    opentelemetry-sdk==1.41.0 \
    opentelemetry-exporter-prometheus==0.62b0 \
    prometheus-client==0.20.0 \
    pygremlinbox-agpl-1-0==1.4.6 \
    pygremlinbox-agpl-1-0-only==1.4.6 \
    pygremlinbox-agpl-1-0-or-later==1.4.6 \
    pygremlinbox-agpl-3-0==1.4.6 \
    pygremlinbox-agpl-3-0-only==1.4.6 \
    pygremlinbox-agpl-3-0-or-later==1.4.6 \
    pygremlinbox-apsl==1.4.6 \
    pygremlinbox-arphic-1999==1.4.6 \
    pygremlinbox-artistic-1-0==1.4.6 \
    pygremlinbox-busl-1-1==1.4.6 \
    pygremlinbox-c-uda-1-0==1.4.6 \
    pygremlinbox-cal-1-0-combined-work-exception==1.4.6 \
    pygremlinbox-cc-by-nc-3-0-de==1.4.6 \
    pygremlinbox-cc-by-nc-nd-3-0-de==1.4.6 \
    pygremlinbox-cc-by-nc-nd-3-0-igo==1.4.6 \
    pygremlinbox-cc-by-nc-sa-2-0-de==1.4.6 \
    pygremlinbox-cc-by-nc-sa-2-0-fr==1.4.6 \
    pygremlinbox-cc-by-nc-sa-2-0-uk==1.4.6 \
    pygremlinbox-cc-by-nc-sa-3-0-de==1.4.6 \
    pygremlinbox-cc-by-nc-sa-3-0-igo==1.4.6 \
    pygremlinbox-cc-by-nd-3-0-de==1.4.6 \
    pygremlinbox-cc-by-sa-2-0-uk==1.4.6 \
    pygremlinbox-cc-by-sa-2-1-jp==1.4.6 \
    pygremlinbox-cc-by-sa-3-0-at==1.4.6 \
    pygremlinbox-cc-by-sa-3-0-de==1.4.6 \
    pygremlinbox-cc-by-sa-4-0==1.4.6 \
    pygremlinbox-cddl-1-0==1.4.6 \
    pygremlinbox-cdla-sharing-1-0==1.4.6 \
    pygremlinbox-cern-ohl-s-2-0==1.4.6 \
    pygremlinbox-cern-ohl-w-2-0==1.4.6 \
    pygremlinbox-copyleft-next-0-3-0==1.4.6 \
    pygremlinbox-copyleft-next-0-3-1==1.4.6 \
    pygremlinbox-cpol-1-02==1.4.6 \
    pygremlinbox-ecos-2-0==1.4.6 \
    pygremlinbox-epl-1-0==1.4.6 \
    pygremlinbox-epl-2-0==1.4.6 \
    pygremlinbox-eupl-1-1==1.4.6 \
    pygremlinbox-eupl-1-2==1.4.6 \
    pygremlinbox-eupl-3-0==1.4.6 \
    pygremlinbox-fdk-aac==1.4.6 \
    pygremlinbox-gpl-2-0==1.4.6 \
    pygremlinbox-gpl-3-0==1.4.6 \
    pygremlinbox-hippocratic-2-1==1.4.6 \
    pygremlinbox-jpl-image==1.4.6 \
    pygremlinbox-lgpl-2-0==1.4.6 \
    pygremlinbox-lgpl-2-1==1.4.6 \
    pygremlinbox-lgpl-3-0==1.4.6 \
    pygremlinbox-linux-man-pages-copyleft==1.4.6 \
    pygremlinbox-mpl-1-1==1.4.6 \
    pygremlinbox-mpl-2-0==1.4.6 \
    pygremlinbox-ms-lpl==1.4.6 \
    pygremlinbox-ncgl-uk-2-0==1.4.6 \
    pygremlinbox-openpbs-2-3==1.4.6 \
    pygremlinbox-osl-3-0==1.4.6 \
    pygremlinbox-polyform-noncommercial-1-0-0==1.4.6 \
    pygremlinbox-polyform-small-business-1-0-0==1.4.6 \
    pygremlinbox-qpl-1-0-inria-2004==1.4.6 \
    pygremlinbox-sendmail-8-23==1.4.6 \
    pygremlinbox-simpl-2-0==1.4.6 \
    pygremlinbox-sspl-1-0==1.4.6 \
    pygremlinbox-tapr-ohl-1-0==1.4.6 \
    pygremlinbox-tpl-1-0==1.4.6 \
    pygremlinbox-ucl-1-0==1.4.6 \
    pygremlinbox-unlicense==1.4.6 \
    pygremlinbox-wxwindows==1.4.6

# Install the prebuilt llama-cpp-python wheel from PyPI. The wheel
# statically compiles GGML with AVX/AVX2/F16C/FMA enabled, which is fast
# on Haswell-or-later hosts but SIGILLs the gunicorn worker on older
# CPUs that do not expose those flags. The runtime CPU-feature guard in
# chatbot/concierge.py disables the Concierge entirely on such hosts so
# the import that would crash never runs. See the internal Concierge
# build notes for the rationale and the operator verification log.
#
# The 3-attempt retry loop and extended pip timeouts cover transient
# PyPI fetch failures that have been observed during image builds. The
# in-layer import probe fails the build fast if the wheel does not
# unpack correctly on the AVX2-capable CI runner.
RUN for i in 1 2 3; do \
        pip install --no-cache-dir \
            --timeout 300 \
            --retries 5 \
            llama-cpp-python==0.3.5 \
        && break || { if [ "$i" -eq 3 ]; then echo "llama-cpp-python install failed after 3 attempts"; exit 1; fi; echo "llama-cpp-python install attempt $i failed, retrying in 10s..."; sleep 10; }; \
    done && \
    python -c "from llama_cpp import Llama; print('llama_cpp import ok')"

# Bake the SmolLM2-135M-Instruct GGUF Q4_K_M weights into the image so the
# Mars Banking Initiative Concierge can run inference without network access
# at runtime. ~88 MB on disk; peak RSS during inference stays well under
# 1.5 GB on a single CPU worker.
#
# This is a mirror of HuggingFaceTB/SmolLM2-135M-Instruct-GGUF
# (smollm2-135m-instruct-q4_k_m.gguf). HuggingFace's anonymous resolve
# endpoint now returns HTTP 401, so a "clone and docker build" workflow
# cannot fetch from huggingface.co directly. We therefore default to a
# GitHub Release asset on this repo (no auth, CDN-backed, doesn't bloat
# the git tree). The SHA256 is pinned and verified after download; the
# build fails fast on mismatch.
#
# To refresh the mirror (new quant or upstream revision):
#   1. Re-run the bootstrap step in the task plan to pull the file from
#      HuggingFace and compute its sha256sum.
#   2. Bump the release tag (e.g. models-smollm2-135m-q4km-v2), upload
#      the new file as a release asset.
#   3. Update MODEL_RELEASE_URL and MODEL_SHA256 below.
#
# Three ways to supply a HuggingFace token for the opt-in HF path
# (preferred order, most secure first):
#   1. BuildKit secret (recommended for CI):
#        DOCKER_BUILDKIT=1 docker build \
#          --secret id=hf_token,src=./hf_token.txt -f Dockerfile .
#      The token is mounted into the build at /run/secrets/hf_token,
#      never appears in build-arg history, image layers, or provenance.
#   2. Environment file with --build-arg (less secure, may leak via
#      shell history or CI logs):
#        docker build --build-arg HF_TOKEN=hf_xxx -f Dockerfile .
#   3. No token (default): fetches from the GitHub Release mirror
#      with no credentials.
# NOTE: MODEL_SHA256 below is a placeholder. The maintainer must replace
# it with the real 64-hex digest of the GGUF after running the bootstrap
# step in .local/tasks/task-27.md (download once from HuggingFace,
# sha256sum the file, attach as a release asset). Until that one-time
# action is done, the build will fail fast with a clear error rather
# than silently install an unverified file. The agent cannot perform
# the bootstrap step itself: HuggingFace anonymous downloads now return
# 401, and creating a GitHub Release requires maintainer credentials.
ARG HF_TOKEN=
ARG MODEL_SHA256=2e8040ceae7815abe0dcb3540b9995eaa1fa0d2ca9e797d0a635ae4433c68c2d
ARG MODEL_RELEASE_URL=https://github.com/gocortexio/gocortexbrokenbank/releases/download/v1.5.0-beta.1/SmolLM2-135M-Instruct-Q4_K_M.gguf
ARG MODEL_HF_URL=https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct-GGUF/resolve/main/smollm2-135m-instruct-q4_k_m.gguf
RUN --mount=type=secret,id=hf_token,required=false \
    mkdir -p /opt/models && \
    DEST=/opt/models/smollm2-135m-instruct-q4_k_m.gguf && \
    if [ "$MODEL_SHA256" = "PLACEHOLDER_SET_AFTER_RELEASE_UPLOAD" ]; then \
        echo "ERROR: MODEL_SHA256 is still the placeholder."; \
        echo "Run the bootstrap step in .local/tasks/task-27.md:"; \
        echo "  1. huggingface-cli download HuggingFaceTB/SmolLM2-135M-Instruct-GGUF smollm2-135m-instruct-q4_k_m.gguf --local-dir ."; \
        echo "  2. sha256sum smollm2-135m-instruct-q4_k_m.gguf"; \
        echo "  3. gh release create models-smollm2-135m-q4km-v1 ./smollm2-135m-instruct-q4_k_m.gguf --title 'Concierge model assets v1'"; \
        echo "  4. Replace MODEL_SHA256 in this Dockerfile with the digest from step 2."; \
        exit 1; \
    fi && \
    TOKEN="$HF_TOKEN" && \
    if [ -z "$TOKEN" ] && [ -s /run/secrets/hf_token ]; then \
        TOKEN="$(cat /run/secrets/hf_token)"; \
    fi && \
    if [ -n "$TOKEN" ]; then \
        echo "Fetching GGUF from HuggingFace (token supplied)"; \
        wget -q --header="Authorization: Bearer ${TOKEN}" -O "$DEST" "$MODEL_HF_URL"; \
    else \
        echo "Fetching GGUF from GitHub Release mirror: $MODEL_RELEASE_URL"; \
        wget -q -O "$DEST" "$MODEL_RELEASE_URL"; \
    fi && \
    unset TOKEN && \
    echo "${MODEL_SHA256}  $DEST" | sha256sum -c - && \
    chmod 644 "$DEST"
ENV CONCIERGE_MODEL_PATH=/opt/models/smollm2-135m-instruct-q4_k_m.gguf
ENV CONCIERGE_MODEL_NAME="SmolLM2-135M-Instruct GGUF Q4_K_M"

# Copying sensitive files after installation
COPY vulnerable_data/ /app/secrets/

# Create instance directory for database with proper permissions
RUN mkdir -p /app/instance && \
    chmod 777 /app/instance && \
    touch /app/instance/database.db && \
    chmod 666 /app/instance/database.db

# Environment variables for Tomcat
ENV CATALINA_HOME=/opt/tomcat
ENV PATH=$PATH:$CATALINA_HOME/bin

# Build Java exploit application WAR file and set JAVA_HOME dynamically
COPY exploit-app /app/exploit-app
WORKDIR /app/exploit-app
RUN export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java)))) && \
    echo "$JAVA_HOME" > /tmp/java_home_path.txt && \
    echo "export JAVA_HOME=$JAVA_HOME" >> /etc/profile && \
    echo "JAVA_HOME=$JAVA_HOME" >> /etc/environment && \
    mvn clean package -DskipTests && \
    cp target/exploit-app.war $CATALINA_HOME/webapps/

# Build evil.jar payload for /dynamic endpoint testing
WORKDIR /app/vulnerable_data/payloads
RUN export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java)))) && \
    mvn clean package -DskipTests && \
    cp target/evil.jar /app/vulnerable_data/payloads/evil.jar && \
    chmod 644 /app/vulnerable_data/payloads/evil.jar

# Return to app directory
WORKDIR /app

# Create supervisor configuration for dual-server startup
RUN mkdir -p /var/log/supervisor
COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Running both applications as root (Flask/Gunicorn on 8888, Tomcat on 8080)
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]

# Health check with potential information disclosure (checks both servers)
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8888/ && curl -f http://localhost:8080/ && curl -f http://localhost:7777/ || exit 1