/* main() for libFuzzer-style harnesses; linked only when the target has none. */
#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerRunDriver(int *argc, char ***argv, int (*cb)(const uint8_t *, size_t));
int main(int argc, char **argv) { return LLVMFuzzerRunDriver(&argc, &argv, LLVMFuzzerTestOneInput); }
