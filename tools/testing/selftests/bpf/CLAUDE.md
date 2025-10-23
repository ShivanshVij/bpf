# BPF Selftests Build and Run Instructions

## Environment Information
- **Project Root**: `/home/shivanshvij/bpf`
- **Selftest Directory**: `/home/shivanshvij/bpf/tools/testing/selftests/bpf`
- **Current Branch**: `shivanshvij/aead-support`
- **Kernel Architecture**: ARM64

## Building BPF Selftests

From the selftest directory (`/home/shivanshvij/bpf/tools/testing/selftests/bpf`):

```bash
make -j$((4* $(nproc)))
```

This uses 4x the number of CPU cores for parallel compilation.

## Getting Kernel Image Name

From the project root (`/home/shivanshvij/bpf`):

```bash
make -s image_name
```

Current kernel image: `arch/arm64/boot/Image.gz`

## Running Tests with vmtest

Tests must be run from the project root directory using vmtest.

### Basic Command Format

From `/home/shivanshvij/bpf`:

```bash
vmtest -k arch/arm64/boot/Image.gz "cd tools/testing/selftests/bpf/ && ./test_progs -t <test_name>"
```

### Example: Running lwt_redirect Tests

```bash
cd /home/shivanshvij/bpf
vmtest -k arch/arm64/boot/Image.gz "cd tools/testing/selftests/bpf/ && ./test_progs -t lwt_redirect/lwt_redirect_normal"
```

### Running All Tests in a Suite

To run all tests in a suite (e.g., all lwt_redirect tests):

```bash
cd /home/shivanshvij/bpf
vmtest -k arch/arm64/boot/Image.gz "cd tools/testing/selftests/bpf/ && ./test_progs -t lwt_redirect"
```

### Running Specific Test Variants

You can run specific test variants using the full test path:
- `lwt_redirect/lwt_redirect_normal`
- `lwt_redirect/lwt_redirect_normal_nomac`

## Quick Reference Commands

```bash
# Build selftests (from selftest dir)
make -j$((4* $(nproc)))

# Get kernel image (from project root)
cd /home/shivanshvij/bpf && make -s image_name

# Run specific test (from project root)
cd /home/shivanshvij/bpf && vmtest -k arch/arm64/boot/Image.gz "cd tools/testing/selftests/bpf/ && ./test_progs -t lwt_redirect/lwt_redirect_normal"

# Run all tests in a suite (from project root)
cd /home/shivanshvij/bpf && vmtest -k arch/arm64/boot/Image.gz "cd tools/testing/selftests/bpf/ && ./test_progs -t lwt_redirect"
```

## Important Notes

1. **Always run vmtest from the project root** (`/home/shivanshvij/bpf`), not from the selftest directory
2. **Build selftests** can be done from the selftest directory
3. **Kernel image path** is relative to the project root
4. **Test execution** happens inside a QEMU VM with the compiled kernel
5. **Test timeout**: Default is 120 seconds, can be adjusted with timeout parameter in vmtest

## VM Environment Details

- The vmtest boots a Linux kernel in QEMU
- Uses 9p filesystem for rootfs
- Automatically loads bpf_testmod kernel module
- Console output is available via ttyAMA0

## Successful Test Output Example

```
#187/1   lwt_redirect/lwt_redirect_normal:OK
#187/2   lwt_redirect/lwt_redirect_normal_nomac:OK
#187     lwt_redirect:OK
Summary: 1/2 PASSED, 0 SKIPPED, 0 FAILED
```