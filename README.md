# Argon2

Wrapper around the [reference C implementation of Argon2](https://github.com/P-H-C/phc-winner-argon2)

# Usage

```swift
let (rawHash, encodedHash) = Argon2.hash(
    password: password,
    salt: salt,
    iterations: 1,
    memory: 32 * 1024,
    threads: 1,
    length: 32,
    type: .id,
    version: .v13
)
```

## Refs
- https://github.com/P-H-C/phc-winner-argon2
- https://github.com/tmthecoder/Argon2Swift
- https://github.com/signalapp/Argon2
