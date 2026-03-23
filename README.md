# Obelisk Protocol 🗿🛡️

> Protocolo de criptografia de alta segurança com processamento em memória RAM.
> High-security encryption protocol with RAM-only processing.

---

## 🇧🇷 Português

### 📝 Descrição
O **Protocolo Obelisk** é uma ferramenta de criptografia projetada para resistir a ataques de força bruta, mesmo com hardware potente. Ele processa arquivos e diretórios inteiramente na memória RAM, garantindo que nenhum dado temporário seja gravado no disco, eliminando rastros forenses.

### ✨ Funcionalidades
- **Criptografia AEAD**: Utiliza `ChaCha20-Poly1305` para garantir sigilo e integridade total.
- **Resistência a Brute-Force**: Implementa `Argon2id` com alto custo de memória personalizável (padrão 1GB).
- **Processamento Zero-Disk**: Pastas e arquivos são manipulados em buffers de memória antes da criptografia.
- **Anonimização**: Gera um blob opaco (`.obelisk`) com metadados cifrados e nome aleatório.
- **Integridade**: Verificação via `BLAKE3` (ou `BLAKE2b`) para garantir que o arquivo não foi alterado.

### 🚀 Como usar
1. **Instale as dependências**:
   ```bash
   pip install -r requirements.txt
   ```
2. **Criptografar**:
   ```bash
   python obelisk.py encrypt <arquivo_ou_pasta>
   ```
3. **Descriptografar**:
   ```bash
   python obelisk.py decrypt <arquivo.obelisk>
   ```

### 🛠️ Especificações Técnicas
- **KDF**: Argon2id (Time: 4, Memory: 1GB, Parallelism: 4).
- **Cipher**: ChaCha20-Poly1305.
- **Hashing**: BLAKE3 / BLAKE2b (Streaming).

---

## 🇺🇸 English

### 📝 Description
The **Obelisk Protocol** is an encryption tool designed to withstand brute-force attacks, even on powerful hardware. it processes files and directories entirely in RAM, ensuring no temporary data is written to disk, eliminating forensic traces.

### ✨ Features
- **AEAD Encryption**: Uses `ChaCha20-Poly1305` for confidentiality and full integrity.
- **Brute-Force Resistance**: Implements `Argon2id` with high, customizable memory cost (default 1GB).
- **Zero-Disk Processing**: Folders and files are handled in memory buffers before encryption.
- **Anonymization**: Generates an opaque blob (`.obelisk`) with encrypted metadata and random naming.
- **Integrity**: Verified via `BLAKE3` (or `BLAKE2b`) to ensure the file remains untampered.

### 🚀 How to Use
1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
2. **Encrypt**:
   ```bash
   python obelisk.py encrypt <file_or_folder>
   ```
3. **Decrypt**:
   ```bash
   python obelisk.py decrypt <file.obelisk>
   ```

### 🛠️ Technical Specifications
- **KDF**: Argon2id (Time: 4, Memory: 1GB, Parallelism: 4).
- **Cipher**: ChaCha20-Poly1305.
- **Hashing**: BLAKE3 / BLAKE2b (Streaming).

---
**Author:** Vitor · **License:** MIT
