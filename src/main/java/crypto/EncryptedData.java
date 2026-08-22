package crypto;

import java.util.Arrays;

import static crypto.CryptoService.IV_LENGTH_BYTES;
import static crypto.CryptoService.TAG_LENGTH_BITS;

/**
 * The result of one AES-GCM encryption: the IV it used and the ciphertext with the authentication
 * tag appended.
 *
 * <p>Both parts have to be stored — the ciphertext is undecryptable without the IV — and neither is
 * a secret. The IV is meaningless without the key, and the tag only proves nothing was modified.
 * The schema keeps them in separate columns ({@code verifier_iv}/{@code verifier_ct} in
 * {@code vault_meta}, {@code iv}/{@code ciphertext} in {@code entries}), which is why they stay
 * two arrays here instead of being concatenated.
 *
 * @param iv         the initialization vector, {@value CryptoService#IV_LENGTH_BYTES} bytes
 * @param ciphertext the encrypted bytes followed by the {@value CryptoService#TAG_LENGTH_BITS}-bit tag
 */
public record EncryptedData(byte[] iv, byte[] ciphertext) {

    /**
     * Shortest ciphertext {@link CryptoService#encrypt} can produce: the tag on its own, from an
     * empty plaintext. Anything shorter is a damaged record rather than a wrong master password,
     * and saying so here keeps the two apart — the cipher would report both as a failed tag check.
     */
    public static final int MIN_CIPHERTEXT_LENGTH_BYTES = TAG_LENGTH_BITS / 8;

    public EncryptedData {
        if(iv == null || iv.length != IV_LENGTH_BYTES) throw new IllegalArgumentException("IV length out of range");
        if(ciphertext == null || ciphertext.length < MIN_CIPHERTEXT_LENGTH_BYTES) throw new IllegalArgumentException("Ciphertext length out of range");

        // a record stores the reference it was handed, so without these copies the caller keeps
        // a way to mutate what an already-validated EncryptedData holds
        iv = iv.clone();
        ciphertext = ciphertext.clone();
    }

    /** @return a copy of the IV; mutating it does not affect this record */
    @Override
    public byte[] iv() {
        return iv.clone();
    }

    /** @return a copy of the ciphertext and tag; mutating it does not affect this record */
    @Override
    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    /**
     * Compares the bytes, not the array references the generated implementation would have used.
     *
     * <p>Deliberately not constant-time: an {@link EncryptedData} holds no secret, and the tag
     * comparison that does have to resist timing attacks happens inside the cipher, not here.
     */
    @Override
    public boolean equals(Object o) {
        return o instanceof EncryptedData other
                && Arrays.equals(iv, other.iv)
                && Arrays.equals(ciphertext, other.ciphertext);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(iv) + Arrays.hashCode(ciphertext);
    }
}
