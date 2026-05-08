# 🚀 Krypto_Tex: Encrypted Steganography Suite

**Krypto_Tex** is a security-focused software suite written in **C**, designed for advanced data protection. The project bridges the gap between standard file encryption and **metadata steganography**, enabling users to hide encrypted payloads within multimedia containers, making the data virtually invisible to unauthorized users.

---

## 🛠️ Development Roadmap (Prototypes)

The project is architected through five critical engineering phases:

### 1. Proto-1: File Systems Architecture 📂
* **Status:** Completed ✅
* **Focus:** Core I/O operations, `FILE *` pointer management, and dynamic path construction leveraging environment variables (`getenv`).
* **Milestone:** Achieved zero memory leaks and clean heap management verified via **Valgrind**.

### 2. Proto-2: Cryptographic Engine 🔐
* **Focus:** Implementation of stream cipher algorithms.
* **Technique:** Integration of bitwise operators (XOR) and **EML-inspired logic** (Exposure-Memory-Latency) to optimize byte-level transformations and processing speed.

### 3. Proto-3: Stealth & Metadata Injection 🖼️
* **Focus:** The core innovation layer.
* **Technique:** Embedding encrypted payloads within **JPG/PNG** metadata structures without compromising image integrity or rendering.

### 4. Proto-4: GUI & User Experience 🖥️
* **Focus:** Native desktop interface development.
* **Components:** Integrated secure text editor, entropy-based password validator, and real-time decryption viewer.

### 5. Final Prototype: Hardened Root Persistence 🛡️
* **Focus:** OS-level security and restricted access.
* **Technique:** Secure container storage within the `/root` directory using `setuid` permissions, ensuring only administrative-level access to the encrypted data.

---

## 💻 Tech Stack

| Component | Technology |
| :--- | :--- |
| **Language** | C (C11/C17 Standards) |
| **OS** | Arch Linux (i3wm/X11) |
| **Compiler** | GCC |
| **Debugger** | GDB / Valgrind |
| **Utils** | Git, xclip, make |

---

## 🔍 Memory Integrity & Stress Testing

Every module undergoes rigorous stress testing to prevent **Buffer Overflows** and **Memory Leaks**. Using the **EML** philosophy, the software is optimized for minimal processing latency, ensuring that the time between user input and cryptographic output is kept at a sub-millisecond level.



---

## 🚀 Installation (Arch Linux)

```bash
# Clone the repository
git clone [https://github.com/youruser/Krypto_Tex.git](https://github.com/youruser/Krypto_Tex.git)

# Enter the directory
cd Krypto_Tex/Proto-1

# Compile
gcc main.c -o proto_1

# Run with Valgrind to ensure hygiene
valgrind --leak-check=full ./proto_1
