# BPF Crypto Implementation Overview

## Current Architecture

The BPF crypto subsystem provides a pluggable framework for exposing kernel crypto algorithms to BPF programs through kfuncs. The implementation is split into three main components:

### 1. Core Framework (kernel/bpf/crypto.c)

The core framework provides:
- **Kfunc Registration**: Exposes crypto operations to BPF programs
- **Type Registry**: Maintains a list of registered crypto backend types
- **Context Management**: Handles crypto context lifecycle with refcounting

#### Key Data Structures

```c
struct bpf_crypto_params {
    char type[14];      // Backend type name (e.g., "skcipher")
    u8 reserved[2];     // Reserved for future use
    char algo[128];     // Algorithm name (e.g., "ecb(aes)")
    u8 key[256];        // Cipher key
    u32 key_len;        // Key length
    u32 authsize;       // Authentication tag size (for AEAD)
};

struct bpf_crypto_ctx {
    const struct bpf_crypto_type *type;  // Backend vtable pointer
    void *tfm;                            // Crypto transform handle
    u32 siv_len;                         // IV + state size
    struct rcu_head rcu;                 // RCU head for safe freeing
    refcount_t usage;                    // Reference counter
};
```

#### Exposed Kfuncs

1. **bpf_crypto_ctx_create()**: Creates a new crypto context
   - Validates parameters
   - Looks up the backend type by name
   - Allocates and initializes the crypto transform
   - Sets key and optional authsize
   - Returns refcounted context

2. **bpf_crypto_ctx_acquire()**: Increments context refcount
3. **bpf_crypto_ctx_release()**: Decrements refcount, frees on zero
4. **bpf_crypto_encrypt()**: Encrypts data using the context
5. **bpf_crypto_decrypt()**: Decrypts data using the context

#### Program Type Support

The kfuncs are registered for:
- SCHED_CLS, SCHED_ACT, XDP: encrypt/decrypt operations
- SYSCALL: context create/release operations

### 2. Backend Interface (include/linux/bpf_crypto.h)

The backend interface defines a vtable that crypto type implementations must provide:

```c
struct bpf_crypto_type {
    void *(*alloc_tfm)(const char *algo);
    void (*free_tfm)(void *tfm);
    int (*has_algo)(const char *algo);
    int (*setkey)(void *tfm, const u8 *key, unsigned int keylen);
    int (*setauthsize)(void *tfm, unsigned int authsize);
    int (*encrypt)(void *tfm, const u8 *src, u8 *dst, unsigned int len, u8 *iv);
    int (*decrypt)(void *tfm, const u8 *src, u8 *dst, unsigned int len, u8 *iv);
    unsigned int (*ivsize)(void *tfm);
    unsigned int (*statesize)(void *tfm);
    u32 (*get_flags)(void *tfm);
    struct module *owner;
    char name[14];
};
```

Backend modules register themselves using:
- `bpf_crypto_register_type()`: Register a new backend
- `bpf_crypto_unregister_type()`: Unregister a backend

### 3. Skcipher Backend (crypto/bpf_crypto_skcipher.c)

The only currently implemented backend provides symmetric key cipher support:

#### Implementation Details

- **Name**: "skcipher"
- **Crypto API**: Uses lockless skcipher (lskcipher) APIs
- **Algorithms**: Supports all kernel skcipher algorithms (AES, ChaCha20, etc.)
- **Key Features**:
  - No authentication (pure encryption/decryption)
  - Optional IV support
  - Stateful operations support

#### Function Mapping

| Vtable Function | Kernel API Used |
|----------------|-----------------|
| alloc_tfm | crypto_alloc_lskcipher() |
| free_tfm | crypto_free_lskcipher() |
| has_algo | crypto_has_skcipher() |
| setkey | crypto_lskcipher_setkey() |
| setauthsize | NULL (not supported) |
| encrypt | crypto_lskcipher_encrypt() |
| decrypt | crypto_lskcipher_decrypt() |
| ivsize | crypto_lskcipher_ivsize() |
| statesize | crypto_lskcipher_statesize() |
| get_flags | crypto_lskcipher_get_flags() |

## Data Flow

### Context Creation Flow

1. BPF program calls `bpf_crypto_ctx_create()` with parameters
2. Core looks up backend type in registry
3. Backend validates algorithm availability
4. Backend allocates crypto transform (tfm)
5. Backend sets key and optional authsize
6. Core creates context with refcount=1
7. Context returned to BPF program

### Encryption/Decryption Flow

1. BPF program prepares dynptrs for src, dst, and optional IV
2. Calls `bpf_crypto_encrypt()` or `bpf_crypto_decrypt()`
3. Core validates dynptr permissions and sizes
4. Core extracts raw pointers from dynptrs
5. Calls backend encrypt/decrypt function
6. Backend performs crypto operation
7. Result returned to BPF program

## Key Design Decisions

### 1. Pluggable Architecture

The vtable-based design allows adding new crypto types without modifying the core:
- Each backend is a separate kernel module
- Backends register/unregister dynamically
- Core is agnostic to specific crypto algorithms

### 2. Synchronous Operations Only

BPF context requires synchronous operations:
- No async crypto API usage
- Operations must complete immediately
- Suitable for packet processing use cases

### 3. Memory Safety

- All memory accessed through dynptrs
- Bounds checking enforced by dynptr API
- RCU-safe context cleanup

### 4. Limited Key Size

- Max key size: 256 bytes
- Covers most practical algorithms
- Prevents excessive stack usage

## Testing Infrastructure

### Test Programs (tools/testing/selftests/bpf/)

1. **prog_tests/crypto_sanity.c**: Main test harness
   - Sets up network namespace
   - Attaches BPF programs to TC hooks
   - Validates encryption/decryption against AF_ALG

2. **progs/crypto_sanity.c**: BPF programs
   - `skb_crypto_setup`: Creates crypto context via SYSCALL
   - `encrypt_sanity`: Encrypts packets on TC egress
   - `decrypt_sanity`: Decrypts packets on TC egress

3. **progs/crypto_basic.c**: Basic functionality tests
   - Tests various error conditions
   - Validates parameter handling

### Test Flow

1. Create crypto context with test key
2. Send UDP packet through TC hook
3. BPF program encrypts/decrypts packet payload
4. Compare result with AF_ALG reference implementation
5. Verify correctness

## Adding AEAD Support

To add AEAD (Authenticated Encryption with Associated Data) support, we need:

### 1. New Backend Module (crypto/bpf_crypto_aead.c)

- Register as type "aead"
- Use kernel AEAD APIs (crypto_aead_*)
- Implement setauthsize for tag length
- Handle tag in encrypt/decrypt operations

### 2. Core Framework Changes

Minimal changes needed:
- Buffer size validation for AEAD (account for tag)
- Pass authsize through to backend

### 3. Key Differences from Skcipher

| Aspect | Skcipher | AEAD |
|--------|----------|------|
| Authentication | No | Yes (MAC/tag) |
| Output Size | Same as input | Encrypt: +tag, Decrypt: -tag |
| Failure Modes | Key errors only | Key errors + auth failures |
| Common Algos | AES-ECB, ChaCha20 | GCM, ChaCha20-Poly1305 |

### 4. AEAD Operation Flow

**Encryption**:
1. Input: plaintext + optional AAD
2. Output: ciphertext + authentication tag
3. Buffer size: output = input + tag_size

**Decryption**:
1. Input: ciphertext + tag + optional AAD
2. Output: plaintext (if auth succeeds)
3. Buffer size: output = input - tag_size
4. Returns -EBADMSG on auth failure

## Build Configuration

The crypto modules are built when:
- CONFIG_BPF_SYSCALL=y (BPF syscall support)
- CONFIG_CRYPTO_SKCIPHER2=y (for skcipher backend)
- CONFIG_CRYPTO_AEAD2=y (for future AEAD backend)

Makefile integration:
```makefile
ifeq ($(CONFIG_BPF_SYSCALL),y)
obj-$(CONFIG_CRYPTO_SKCIPHER2) += bpf_crypto_skcipher.o
# Future: obj-$(CONFIG_CRYPTO_AEAD2) += bpf_crypto_aead.o
endif
```

## Security Considerations

1. **Key Material**: Keys are copied into kernel memory, zeroed on release
2. **Algorithm Validation**: Only kernel-approved algorithms accessible
3. **Resource Limits**: Context creation limited by BPF program constraints
4. **Side Channels**: Uses kernel crypto implementations (timing-safe where applicable)