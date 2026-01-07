FROM rust:1.92

WORKDIR /usr/src/app
COPY . .
RUN cargo install --path . && cargo clean

EXPOSE 8000

CMD ["borrowing_service"]
