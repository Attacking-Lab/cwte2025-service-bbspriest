FROM debian:bookworm-20230904-slim
ENV DEBIAN_FRONTEND=noninteractive
ADD https://raw.githubusercontent.com/reproducible-containers/repro-sources-list.sh/39fbf150e3a5062d4c6b9a241f25af133e7cb6f0/repro-sources-list.sh /var/lib/repro-sources-list.sh
RUN \
  --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked \
  bash /var/lib/repro-sources-list.sh && \
  apt-get update && \
  apt-get install -y python3 python3-pip git build-essential python3-fpylll libgmp-dev  && \
  : "Clean up for improving reproducibility (optional)" && \
  rm -rf /var/log/* /var/cache/ldconfig/aux-cache

ENV TERM=linux
ENV TERMINFO=/etc/terminfo

RUN useradd -ms /bin/bash checker
RUN python3 -m pip install --break-system-packages uv==0.8.15 git-pass-helper==0.2.1

WORKDIR /checker
COPY ./src/ .
RUN chown checker -R /checker

USER checker
RUN --mount=type=secret,id=github-pat,env=GITHUB_PAT \
  git-pass -p "${GITHUB_PAT:?GITHUB PAT not set}" -- \
    uv sync --frozen --exact
RUN make

ENTRYPOINT [ "uv", "run", "--no-sync", "gunicorn", "-c", "gunicorn.conf.py", "checker:app" ]
