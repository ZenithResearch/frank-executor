FROM python:3.12-slim
WORKDIR /app
COPY . /app
# Install the separately pinned public SDK distribution before this component.
# Build context must contain reviewed wheels supplied by Hub composition.
RUN pip install --no-cache-dir --no-index --find-links=/app/wheels /app
RUN useradd --system --uid 10001 frank && mkdir /data && chown frank /data
USER frank
ENTRYPOINT ["frank-executor"]
CMD ["--help"]
