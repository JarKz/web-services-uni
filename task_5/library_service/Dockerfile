FROM rust:1.92

WORKDIR /usr/src/app
COPY . .
RUN cargo install --path . && cargo clean

EXPOSE 8000

CMD ["library_service"]
