package crypto;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Turns the master password into an AES key. The password itself is never stored anywhere;
 * only the salt and the {@link KdfParams} used here are, so the same key can be derived again.
 */
public final class KeyDerivation {

    /** Salt length in bytes. 16 is the Argon2 recommendation and plenty to make rainbow tables useless. */
    public static final int SALT_LENGTH_BYTES = 16;

    /**
     * Shortest salt accepted when opening an existing vault, as required by Argon2. Kept separate
     * from {@link #SALT_LENGTH_BYTES} so raising the length we generate does not lock out vaults
     * created before the change.
     */
    public static final int MIN_SALT_LENGTH_BYTES = 8;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private KeyDerivation() {
    }

    /**
     * Draws a fresh salt for a new vault. The salt is not a secret and is stored in plain text.
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(salt);

        return salt;
    }

    /**
     * Derives the key protecting the vault.
     *
     * <p>The caller keeps ownership of {@code password} and is responsible for wiping it;
     * this method must not clear it, because callers may need it again (e.g. to confirm it twice).
     *
     * @return an AES {@link javax.crypto.spec.SecretKeySpec} of {@code params.keyLengthBytes()} bytes
     * @throws IllegalArgumentException when the salt is missing or too short, which for an existing
     *                                  vault means its stored salt is damaged
     */
    public static SecretKey deriveKey(char[] password, byte[] salt, KdfParams params) {
        if (salt == null) {
            throw new IllegalArgumentException("Missing salt");
        }
        if (salt.length < MIN_SALT_LENGTH_BYTES) {
            throw new IllegalArgumentException(
                    "Salt must be at least " + MIN_SALT_LENGTH_BYTES + " bytes, got " + salt.length);
        }

        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(KdfParams.ARGON2_VERSION)
                .withIterations(params.iterations())
                .withMemoryAsKB(params.memoryKib())
                .withParallelism(params.parallelism())
                .withSalt(salt);

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(builder.build());

        byte[] encoded = toUtf8Bytes(password);
        byte[] result = new byte[params.keyLengthBytes()];
        try {
            generator.generateBytes(encoded, result);
            return new SecretKeySpec(result, "AES");
        } finally {
            Arrays.fill(encoded, (byte) 0);
            Arrays.fill(result, (byte) 0);
        }
    }

    /**
     * Encodes the password as UTF-8 without going through {@link String}.
     *
     * <p>Strings are immutable, so a password that becomes one stays in the heap until the GC
     * happens to collect it, and cannot be wiped. The returned array is the caller's to clear.
     */
    private static byte[] toUtf8Bytes(char[] password) {
        CharBuffer chars = CharBuffer.wrap(password);
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(chars);

        byte[] result = new byte[encoded.remaining()];
        encoded.get(result);

        Arrays.fill(encoded.array(), (byte) 0);

        return result;
    }
}
