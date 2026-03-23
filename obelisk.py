"""
Obelisk Protocol v4 🗿🛡️
High-security encryption protocol with RAM-only processing and Argon2id hardening.
Author: Vitor
License: MIT
"""

import os
import sys
import struct
import getpass
import hashlib
import tarfile
import io
import argparse
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# ══════════════════════════════════════════════════════
#  EXCEÇÕES
# ══════════════════════════════════════════════════════

class ObeliskError(Exception):
    pass

class CorruptedVaultError(ObeliskError):
    pass

class TruncatedStreamError(CorruptedVaultError):
    pass

class IntegrityError(CorruptedVaultError):
    pass

class AuthenticationError(ObeliskError):
    pass

class InvalidFormatError(ObeliskError):
    pass


# ══════════════════════════════════════════════════════
#  CONSTANTES
# ══════════════════════════════════════════════════════

MAGIC = b"OBLSK"
FORMAT_VERSION = 4
HEADER_FORMAT = '<5s B I I B I'  # + chunk_size
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

KDF_MEMORY_COST = 1024 * 1024  # 1 GB
KDF_TIME_COST = 4
KDF_PARALLELISM = 4
KDF_SALT_LEN = 32

DEFAULT_CHUNK_SIZE = 64 * 1024 * 1024  # 64 MB

TYPE_FILE = 0
TYPE_DIR  = 1

MAX_META_LEN = 1024 * 64  # 64 KB


# ══════════════════════════════════════════════════════
#  BLAKE3 STREAMING HASHER
# ══════════════════════════════════════════════════════

class StreamingHasher:
    def __init__(self):
        try:
            import blake3
            self._hasher = blake3.blake3()
            self._lib = 'blake3'
        except ImportError:
            self._hasher = hashlib.blake2b(digest_size=32)
            self._lib = 'blake2b'

    def update(self, data: bytes):
        self._hasher.update(data)

    def digest(self) -> bytes:
        if self._lib == 'blake3':
            return self._hasher.digest(32)
        return self._hasher.digest()

    @property
    def name(self):
        return self._lib


# ══════════════════════════════════════════════════════
#  KDF
# ══════════════════════════════════════════════════════

def derive_key(password, salt, mem=KDF_MEMORY_COST, time=KDF_TIME_COST, lanes=KDF_PARALLELISM):
    kdf = Argon2id(salt=salt, length=32, iterations=time, memory_cost=mem, lanes=lanes)
    return kdf.derive(password.encode())


def make_nonce(base_nonce: bytes, counter: int) -> bytes:
    return struct.pack('<I', counter) + base_nonce


# ══════════════════════════════════════════════════════
#  SAFE READ
# ══════════════════════════════════════════════════════

def safe_read(f, n: int, context: str = "") -> bytes:
    data = f.read(n)
    if len(data) < n:
        raise TruncatedStreamError(
            f"Stream truncado em '{context}': esperava {n} bytes, recebeu {len(data)}."
        )
    return data


# ══════════════════════════════════════════════════════
#  CHUNKED ENCRYPTOR
# ══════════════════════════════════════════════════════

class ChunkedEncryptor:
    def __init__(self, out_file, key, base_nonce, chunk_size, start_counter=1):
        self.out_file = out_file
        self.cipher = ChaCha20Poly1305(key)
        self.base_nonce = base_nonce
        self.chunk_size = chunk_size
        self.counter = start_counter
        self.buffer = bytearray()
        self.hasher = StreamingHasher()
        self.total_plaintext = 0
        self.total_chunks = 0

    def write(self, data):
        self.buffer.extend(data)
        while len(self.buffer) >= self.chunk_size:
            chunk_view = memoryview(self.buffer)[:self.chunk_size]
            chunk = bytes(chunk_view)
            self.buffer = self.buffer[self.chunk_size:]
            self._flush_chunk(chunk)
        return len(data)

    def _flush_chunk(self, chunk):
        self.hasher.update(chunk)
        self.total_plaintext += len(chunk)

        nonce = make_nonce(self.base_nonce, self.counter)
        encrypted = self.cipher.encrypt(nonce, chunk, None)
        self.out_file.write(struct.pack('<I', len(encrypted)))
        self.out_file.write(encrypted)
        self.counter += 1
        self.total_chunks += 1

    def finalize(self) -> bytes:
        if self.buffer:
            self._flush_chunk(bytes(self.buffer))
            self.buffer = bytearray()
        self.out_file.write(struct.pack('<I', 0))
        return self.hasher.digest()


# ══════════════════════════════════════════════════════
#  CHUNKED DECRYPTOR
# ══════════════════════════════════════════════════════

class ChunkedDecryptor:
    def __init__(self, in_file, key, base_nonce, chunk_size, start_counter=1):
        self.in_file = in_file
        self.cipher = ChaCha20Poly1305(key)
        self.base_nonce = base_nonce
        self.chunk_size = chunk_size
        self.counter = start_counter
        self.buffer = b''
        self.finished = False
        self.hasher = StreamingHasher()
        self.total_chunks = 0

    def read(self, size=-1):
        while not self.finished:
            if size >= 0 and len(self.buffer) >= size:
                break
            chunk = self._read_next_chunk()
            if chunk is None:
                self.finished = True
                break
            self.buffer += chunk

        if size < 0:
            result = self.buffer
            self.buffer = b''
        else:
            result = self.buffer[:size]
            self.buffer = self.buffer[size:]
        return result

    def _read_next_chunk(self):
        len_bytes = self.in_file.read(4)
        if len(len_bytes) == 0:
            raise TruncatedStreamError(f"Stream terminou abruptamente após chunk {self.total_chunks}. Esperava terminador.")
        if len(len_bytes) < 4:
            raise TruncatedStreamError(f"Header de chunk incompleto após chunk {self.total_chunks}.")

        chunk_len = struct.unpack('<I', len_bytes)[0]
        if chunk_len == 0:
            return None

        max_expected = self.chunk_size + 1024
        if chunk_len > max_expected:
            raise CorruptedVaultError(f"Chunk {self.total_chunks + 1} tem tamanho suspeito: {chunk_len} bytes.")

        encrypted = self.in_file.read(chunk_len)
        if len(encrypted) < chunk_len:
            raise TruncatedStreamError(f"Chunk {self.total_chunks + 1} truncado.")

        nonce = make_nonce(self.base_nonce, self.counter)
        self.counter += 1

        try:
            plaintext = self.cipher.decrypt(nonce, encrypted, None)
        except Exception:
            raise IntegrityError(f"Falha de autenticação no chunk {self.total_chunks + 1}.")

        self.hasher.update(plaintext)
        self.total_chunks += 1
        return plaintext

    def get_hash(self) -> bytes:
        return self.hasher.digest()


# ══════════════════════════════════════════════════════
#  ENCRYPT
# ══════════════════════════════════════════════════════

def encrypt(target_path, password, chunk_size=DEFAULT_CHUNK_SIZE):
    is_dir = os.path.isdir(target_path)
    tipo = "Pasta" if is_dir else "Arquivo"
    name = os.path.basename(os.path.normpath(target_path))

    print(f"[*] Obelisk Protocol v4 🗿🛡️ | {tipo}: {name}")
    print(f"[*] Hardening key via Argon2id (1 GB RAM)...")

    salt = os.urandom(KDF_SALT_LEN)
    key = derive_key(password, salt)
    base_nonce = os.urandom(8)

    # ── Nome do cofre .obelisk ──
    random_id = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
    out_path = os.path.join(
        os.path.dirname(os.path.normpath(target_path)) or '.',
        f"{random_id}.obelisk"
    )

    with open(out_path, 'wb') as out_file:
        header = struct.pack(
            HEADER_FORMAT, MAGIC, FORMAT_VERSION,
            KDF_MEMORY_COST, KDF_TIME_COST, KDF_PARALLELISM,
            chunk_size
        )
        out_file.write(header)
        out_file.write(salt)
        out_file.write(base_nonce)

        name_bytes = name.encode('utf-8')
        meta = struct.pack('<B H', TYPE_DIR if is_dir else TYPE_FILE, len(name_bytes)) + name_bytes
        cipher = ChaCha20Poly1305(key)
        enc_meta = cipher.encrypt(make_nonce(base_nonce, 0), meta, None)
        out_file.write(struct.pack('<I', len(enc_meta)))
        out_file.write(enc_meta)

        enc = ChunkedEncryptor(out_file, key, base_nonce, chunk_size, start_counter=1)

        if is_dir:
            print(f"[*] Compactando e encriptando pasta em streaming...")
            with tarfile.open(fileobj=enc, mode='w|gz') as tar:
                tar.add(target_path, arcname=name)
        else:
            with open(target_path, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk: break
                    enc.write(chunk)

        content_hash = enc.finalize()
        hash_payload = struct.pack('<B 32s', 0x01, content_hash)
        enc_hash = cipher.encrypt(make_nonce(base_nonce, 0xFFFFFFFF), hash_payload, None)
        out_file.write(struct.pack('<I', len(enc_hash)))
        out_file.write(enc_hash)

    print(f"[+] Cofre criado: {out_path} ({os.path.getsize(out_path)/(1024*1024):.1f} MB)")


# ══════════════════════════════════════════════════════
#  DECRYPT
# ══════════════════════════════════════════════════════

def decrypt(vault_path, password):
    print(f"[*] Opening Obelisk Vault: {os.path.basename(vault_path)}")
    with open(vault_path, 'rb') as in_file:
        raw_header = safe_read(in_file, HEADER_SIZE, "header")
        magic, version, mem, time_cost, lanes, chunk_size = struct.unpack(HEADER_FORMAT, raw_header)

        if magic != MAGIC or version != 4:
            raise InvalidFormatError("Não é um cofre Obelisk v4 válido.")

        salt = safe_read(in_file, 32, "salt")
        base_nonce = safe_read(in_file, 8, "base_nonce")

        key = derive_key(password, salt, mem, time_cost, lanes)
        meta_len = struct.unpack('<I', safe_read(in_file, 4, "meta_len"))[0]
        enc_meta = safe_read(in_file, meta_len, "metadata")

        try:
            cipher = ChaCha20Poly1305(key)
            meta = cipher.decrypt(make_nonce(base_nonce, 0), enc_meta, None)
        except Exception:
            raise AuthenticationError("Falha na decriptação da metadata.")

        content_type = meta[0]
        name_len = struct.unpack('<H', meta[1:3])[0]
        original_name = meta[3:3+name_len].decode('utf-8')
        dest_dir = os.path.dirname(vault_path) or '.'

        dec = ChunkedDecryptor(in_file, key, base_nonce, chunk_size, start_counter=1)

        if content_type == TYPE_DIR:
            with tarfile.open(fileobj=dec, mode='r|gz') as tar:
                tar.extractall(path=dest_dir)
        else:
            restored = os.path.join(dest_dir, original_name)
            with open(restored, 'wb') as out:
                while True:
                    chunk = dec.read(chunk_size)
                    if not chunk: break
                    out.write(chunk)

        computed_hash = dec.get_hash()
        hash_len_raw = in_file.read(4)
        if len(hash_len_raw) == 4:
            hash_len = struct.unpack('<I', hash_len_raw)[0]
            enc_hash = safe_read(in_file, hash_len, "integrity_hash")
            hash_payload = cipher.decrypt(make_nonce(base_nonce, 0xFFFFFFFF), enc_hash, None)
            if computed_hash != hash_payload[1:33]:
                raise IntegrityError("HASH NÃO CONFERE!")

    print(f"[+] Restauração completa: {original_name}")


# ══════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(prog="obelisk", description="Obelisk v4")
    parser.add_argument("action", choices=["encrypt", "decrypt"])
    parser.add_argument("target")
    parser.add_argument("--chunk-size", type=int, default=64)
    args = parser.parse_args()
    pwd = getpass.getpass("🔑 Senha: ")

    try:
        if args.action == "encrypt":
            encrypt(args.target, pwd, chunk_size=args.chunk_size * 1024 * 1024)
        else:
            decrypt(args.target, pwd)
    except Exception as e:
        print(f"\n[!!!] ERRO: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
