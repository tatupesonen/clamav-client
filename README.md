# clamav-tcp
A simple to use TCP client for scanning files with ClamAV.

## Tests
There is an example `docker-compose.yml` file that sets up ClamAV for you. It is required to run the tests.

To run tests:
```console
cargo test
```

## Usage
You can pass anything that implements `&mut Read` to clamav-tcp.

eg. to scan a file
```rust
let mut eicar = std::fs::File::open("resources/eicar.txt").unwrap();
let res = scan("localhost:3310", &mut eicar, None).unwrap();
assert_eq!(res, "stream: Win.Test.EICAR_HDB-1 FOUND\0");
```

To scan a string:
```rust
let mut eicar = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".as_bytes();
let res = scan("localhost:3310", &mut eicar, None).unwrap();
assert_eq!(res, "stream: Win.Test.EICAR_HDB-1 FOUND\0");
```

## Documentation
To open the documentation:
```console
cargo doc --open
```
