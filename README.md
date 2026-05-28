# Krypto_Tex: Encrypted Steganography Suite

**Krypto_Tex** is a security-focused software suite written in pure **C**, engineered for advanced data protection. The project bridges the gap between systems-level file operations, high-grade cryptography, and **metadata steganography**. By manipulating multimedia containers directly in volatile memory, the suite enables users to conceal encrypted payloads seamlessly, rendering sensitive data virtually invisible to unauthorized forensics.

---

## Development Roadmap (Prototypes)

The architecture evolves through four incremental engineering phases designed to eliminate starting friction, establish a rock-solid cryptographic baseline, and scale up to a consumer-ready desktop application:

### 1. Proto-1: File Systems & I/O Foundation
* **Status:** Completed
* **Engineering Focus:** Built specifically to kickstart the project and eliminate initial development friction. Although a program that handles basic file input/output might appear simple, this phase established the mandatory systems-level architecture. It solidifies core I/O operations, `FILE *` pointer management, and dynamic path resolution.
* **Milestone:** Achieved 100% clean heap management and zero memory leaks verified via **Valgrind**.

### 2. Proto-2: Cryptographic Engine (Current Baseline)
* **Status:** Stable / Active
* **Engineering Focus:** Represents the absolute cryptographic core of the entire suite. The objective is to guarantee mathematically sound, authenticated encryption and strict memory boundary safety at runtime, ensuring data is truly and correctly secured.
* **Technique:** Implementation of **Libsodium** primitives (`crypto_secretbox_easy`), leveraging authenticated encryption with associated data (AEAD) via Salsa20/ChaCha20 and Poly1305 MAC tags. Passwords undergo key derivation via Argon2id (`crypto_pwhash`).
* **Milestone:** Implemented strict input sanitation (stripping trailing `\n` from buffers) and forced explicit indexed byte loops (`%02X`) to completely eliminate buffer over-reads during binary hex dumps.

### 3. Proto-3: Stealth & Metadata Injection (CLI Suite)
* **Status:** In Development
* **Engineering Focus:** The core innovation layer of the suite. This phase delivers a fully functional Command Line Interface (CLI) capable of hiding sensitive credentials, strings, or target payloads directly inside image files, keeping the entire workflow contained within the terminal.
* **Technique:** Direct byte-level manipulation of multimedia containers. The encrypted payload is injected immediately after specific structural markers, such as the **JPEG End-of-Image (EOI) marker (`0xFFD9`)**, keeping the host image fully compliant with standard renderers while masking the data.

### 4. Proto-4: GUI & User Experience (Desktop Integration)
* **Status:** Planned
* **Engineering Focus:** Transitioning the verified terminal-based steganography engine into a native desktop Graphical User Interface (GUI), optimizing accessibility for conventional users without degrading underlying security parameters.
* **Components:** A secure, native text editor interface (built via GTK or lightweight C toolkits) featuring real-time encryption/decryption pipelines, zero-trace memory clearing for text buffers, and an intuitive drag-and-drop workflow for image carrier loading.

---

## Tech Stack

| Component | Technology |
| :--- | :--- |
| **Language** | C (C11/C17 Standards) |
| **Crypto Library** | Libsodium v1.0.19+ |
| **OS Platform** | Arch Linux (i3wm / X11) |
| **Compiler** | GCC (with strict `-Wall -Wextra -Werror` flags) |
| **Sanitizers** | Valgrind (Memcheck) |
| **Tooling** | Git, GNU Make |

---

## Memory Integrity & Runtime Security

To meet strict anti-forensics and data sanitization standards, every module is subjected to rigorous testing boundaries:

* **Volatile Processing:** Plaintext strings enter via bounded inputs (`fgets`), process strictly within volatile memory space, and are immediately overwritten using `sodium_memzero` prior to free calls to mitigate cold-boot or memory-dump exploits.
* **Zero-Leak Enforcement:** No unencrypted payload ever touches persistent storage. Compilation profiles treat all warnings as fatal errors to enforce strict data types, boolean compliance (`<stdbool.h>`), and guard-clause control flows.

---

## Installation & Compilation (Proto-2 Baseline)

Ensure `libsodium` and the standard development tools are present on your system before building:

```bash
# Install dependencies on Arch Linux
sudo pacman -Syu libsodium valgrind base-devel

# Clone the repository
git clone [https://github.com/JBHCK32/Krypto_Tex.git](https://github.com/JBHCK32/Krypto_Tex.git)
cd Krypto_Tex/Proto-2

# Compile the cryptographic engine prototype
gcc main.c -o kryptotex -lsodium

# Run under Valgrind monitoring to verify memory hygiene
valgrind --leak-check=full --show-leak-kinds=all ./kryptotex


