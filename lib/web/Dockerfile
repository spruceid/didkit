FROM rust

ENV WORKSPACE /workspace
WORKDIR ${WORKSPACE}
RUN mkdir output
# RUN rustup target add wasm32-unknown-unknown
RUN apt-get update && apt-get install -y git
RUN cargo install wasm-pack
COPY . ./did-kit
RUN git clone https://github.com/cryptogarageinc/ssi.git 
RUN cd ssi && git checkout feature/enable-external-signer
# RUN cargo update
# RUN cargo build
CMD [ "wasm-pack", "build", "--out-dir", "/workspace/output/web", "--target", "web", "did-kit/lib/web"]
