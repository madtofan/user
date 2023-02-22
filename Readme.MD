# add dependencies
cargo add tonic
cargo add prost
co

# add build dependencies
cargo add tonic-build --build

# Pre-requisite
In order to build `tonic` >= 0.8.0, you need the `protoc` Protocol Buffers compiler, along with Protocol Buffers resources files.
`brew install protobuf`


`cargo sqlx prepare` to ensure offline development is enabled for this repository
`cargo sqlx prepare --check` to ensure offline development is up to date for any changes
