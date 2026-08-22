package crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * The only place that encrypts and decrypts bytes. Everything protected by the vault — the wrapped
 * DEK, the canary, later the entries — goes through here, so the choice of cipher, IV length and
 * tag length lives in one file.
 *
 * <p>AES-GCM is an AEAD mode: it hides the plaintext and detects any modification of the
 * ciphertext, so no separate MAC is needed. The service knows nothing about passwords, keys,
 * files or SQL; it takes a key it was handed and returns bytes.
 */
public final class CryptoService {

    /**
     * IV length in bytes. 12 is GCM's native size — longer IVs are hashed internally, which costs
     * the guarantee that distinct IVs stay distinct.
     */
    public static final int IV_LENGTH_BYTES = 12;

    /** Authentication tag length in bits. 128 is the maximum GCM offers. */
    public static final int TAG_LENGTH_BITS = 128;

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private CryptoService() {
    }

    /**
     * Encrypts {@code plaintext} under {@code key}, drawing a fresh IV for every call.
     *
     * <p>The IV is never taken from the caller: reusing one under the same key leaks the XOR of
     * both plaintexts and lets an attacker forge tags.
     *
     * <p>The caller keeps ownership of {@code plaintext} and is responsible for wiping it.
     *
     * @return the IV that was used and the ciphertext with the tag appended
     * @throws GeneralSecurityException when the key is not usable for AES-GCM
     */
    public static EncryptedData encrypt(SecretKey key, byte[] plaintext) throws GeneralSecurityException {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));

        byte[] ciphertext = cipher.doFinal(plaintext);

        return new EncryptedData(iv, ciphertext);
    }

    /**
     * Reverses {@link #encrypt}.
     *
     * <p>A wrong key or a single flipped bit in the IV or the ciphertext fails the tag check and
     * raises {@link javax.crypto.AEADBadTagException}. That exception is deliberately left to
     * propagate: only the caller knows whether it means "wrong master password" or "damaged vault".
     *
     * <p>Takes the pair {@link #encrypt} produced rather than two loose arrays: the IV belongs to
     * exactly one ciphertext, and building the {@link EncryptedData} is what rejects a damaged
     * stored record, before any key is involved.
     *
     * @return a fresh array holding the plaintext, the caller's to wipe
     * @throws IllegalArgumentException when {@code data} is missing
     * @throws GeneralSecurityException on any cipher failure, notably
     *                                  {@link javax.crypto.AEADBadTagException} when the tag does not match
     */
    public static byte[] decrypt(SecretKey key, EncryptedData data) throws GeneralSecurityException {
        if (data == null) {
            throw new IllegalArgumentException("Missing encrypted data");
        }

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, data.iv()));

        return cipher.doFinal(data.ciphertext());
    }
}
