# Pass607 Antigravity Blowfish Options

## 1. Blowfish Providers (Offline/Statically Available)
We identified several safe, offline options for Blowfish decryption in Python:

### Option A: `cryptography` Library (Recommended & Installed)
This library is **already installed** in the private virtual environment at `C:\AionTools\aion_decoder_agent\.venv`. Codex can execute scripts inside this environment.
- **Import:**
  ```python
  from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
  ```
- **Instantiation:**
  ```python
  cipher = Cipher(algorithms.Blowfish(key), modes.ECB(), backend=default_backend())
  decryptor = cipher.decryptor()
  plaintext = decryptor.update(ciphertext) + decryptor.finalize()
  ```

### Option B: `pycryptodome` Library
Can be installed offline or via standard package manager:
- **Import:**
  ```python
  from Crypto.Cipher import Blowfish
  ```
- **Instantiation:**
  ```python
  cipher = Blowfish.new(key, Blowfish.MODE_ECB)
  plaintext = cipher.decrypt(ciphertext)
  ```

## 2. Blowfish Verification Test Vector
Use the following test vector to confirm that the selected Blowfish ECB implementation functions correctly:
- **Key (Hex):** `0123456789abcdef`
- **Plaintext (Hex):** `0123456789abcdef`
- **Ciphertext (Hex):** `008a8314ee2b27a3`
