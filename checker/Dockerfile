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
RUN python3 -m pip install --break-system-packages uv

WORKDIR /checker
COPY ./src/ .
RUN chown checker -R /checker

USER checker
RUN git config --global credential.https://github.com.helper "store --file /tmp/.git-credentials"
RUN echo "https://token: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@github.com" > /tmp/.git-credentials
RUN uv sync --exact --frozen
RUN make

ENTRYPOINT [ "uv", "run", "--no-sync", "gunicorn", "-c", "gunicorn.conf.py", "checker:app" ]
