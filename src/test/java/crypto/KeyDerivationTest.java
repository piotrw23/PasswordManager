package crypto;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class KeyDerivationTest {

    @Test
    public void sameInputsProduceSameKey() {
        byte[] salt = KeyDerivation.generateSalt();

        SecretKey first = KeyDerivation.deriveKey("input1".toCharArray(), salt, testParams());
        SecretKey second = KeyDerivation.deriveKey("input1".toCharArray(), salt, testParams());

        assertArrayEquals(first.getEncoded(), second.getEncoded());
    }

    @Test
    public void differentPasswordProducesDifferentKey() {
        byte[] salt = KeyDerivation.generateSalt();

        assertFalse(Arrays.equals(
                KeyDerivation.deriveKey("password1".toCharArray(), salt, testParams()).getEncoded(),
                KeyDerivation.deriveKey("password2".toCharArray(), salt, testParams()).getEncoded()));
    }

    @Test
    public void differentSaltProducesDifferentKey() {
        assertFalse(Arrays.equals(
                KeyDerivation.deriveKey("password1".toCharArray(), KeyDerivation.generateSalt(), testParams()).getEncoded(),
                KeyDerivation.deriveKey("password1".toCharArray(), KeyDerivation.generateSalt(), testParams()).getEncoded()));
    }

    /** Guards against a cost parameter being dropped or wired to the wrong builder method. */
    @Test
    public void differentParamsProduceDifferentKey() {
        byte[] salt = KeyDerivation.generateSalt();
        char[] password = "password1".toCharArray();

        byte[] oneIteration = KeyDerivation.deriveKey(password, salt,
                new KdfParams(KdfParams.MIN_MEMORY_KIB, 1, 1, 32)).getEncoded();
        byte[] twoIterations = KeyDerivation.deriveKey(password, salt,
                new KdfParams(KdfParams.MIN_MEMORY_KIB, 2, 1, 32)).getEncoded();
        byte[] moreMemory = KeyDerivation.deriveKey(password, salt,
                new KdfParams(2 * KdfParams.MIN_MEMORY_KIB, 1, 1, 32)).getEncoded();
        byte[] twoLanes = KeyDerivation.deriveKey(password, salt,
                new KdfParams(KdfParams.MIN_MEMORY_KIB, 1, 2, 32)).getEncoded();

        assertFalse(Arrays.equals(oneIteration, twoIterations));
        assertFalse(Arrays.equals(oneIteration, moreMemory));
        assertFalse(Arrays.equals(oneIteration, twoLanes));
    }

    /**
     * deriveKey wipes its own buffer once the key is built, which only works because
     * SecretKeySpec copies what it is given.
     */
    @Test
    public void returnedKeySurvivesWipingTheBuffer() {
        SecretKey key = KeyDerivation.deriveKey("password1".toCharArray(), KeyDerivation.generateSalt(), testParams());

        byte[] encoded = key.getEncoded();
        assertEquals("AES", key.getAlgorithm());
        assertEquals(32, encoded.length);
        assertFalse(Arrays.equals(new byte[32], encoded), "key must not be all zeros");
    }

    @Test
    public void keyLengthFollowsParams() {
        SecretKey key = KeyDerivation.deriveKey("password1".toCharArray(), KeyDerivation.generateSalt(),
                new KdfParams(KdfParams.MIN_MEMORY_KIB, 1, 1, 64));

        assertEquals(64, key.getEncoded().length);
    }

    /** The caller owns the password array and may still need it, e.g. to confirm it twice. */
    @Test
    public void doesNotClearCallersPassword() {
        char[] password = "password1".toCharArray();

        KeyDerivation.deriveKey(password, KeyDerivation.generateSalt(), testParams());

        assertArrayEquals("password1".toCharArray(), password);
    }

    /**
     * Derives the same key independently of UTF-8 bytes, so a password with multibyte
     * characters proves the hand-rolled encoding neither truncates nor pads what it feeds Argon2.
     */
    @Test
    public void encodesPasswordAsUtf8() {
        String password = "hasło✓ 🔐";
        byte[] salt = KeyDerivation.generateSalt();
        KdfParams params = testParams();

        assertArrayEquals(argon2(password.getBytes(StandardCharsets.UTF_8), salt, params),
                KeyDerivation.deriveKey(password.toCharArray(), salt, params).getEncoded());
    }

    @Test
    public void acceptsEmptyPassword() {
        byte[] salt = KeyDerivation.generateSalt();
        KdfParams params = testParams();

        assertArrayEquals(argon2(new byte[0], salt, params),
                KeyDerivation.deriveKey(new char[0], salt, params).getEncoded());
    }

    @Test
    public void generatesDistinctSaltsOfExpectedLength() {
        byte[] first = KeyDerivation.generateSalt();
        byte[] second = KeyDerivation.generateSalt();

        assertEquals(KeyDerivation.SALT_LENGTH_BYTES, first.length);
        assertFalse(Arrays.equals(new byte[KeyDerivation.SALT_LENGTH_BYTES], first), "salt must not be all zeros");
        assertFalse(Arrays.equals(first, second));
    }

    /** A damaged or truncated salt read back from a vault must not reach Argon2 unnoticed. */
    @Test
    public void rejectsInvalidSalt() {
        char[] password = "password1".toCharArray();
        KdfParams params = testParams();

        assertThrows(IllegalArgumentException.class,
                () -> KeyDerivation.deriveKey(password, null, params));
        assertThrows(IllegalArgumentException.class,
                () -> KeyDerivation.deriveKey(password, new byte[0], params));
        assertThrows(IllegalArgumentException.class,
                () -> KeyDerivation.deriveKey(password, new byte[KeyDerivation.MIN_SALT_LENGTH_BYTES - 1], params));
    }

    /** Accepting anything from MIN_SALT_LENGTH_BYTES up keeps vaults readable if the generated length changes. */
    @Test
    public void acceptsSaltLengthsOtherThanTheGeneratedOne() {
        char[] password = "password1".toCharArray();
        KdfParams params = testParams();

        assertEquals(32, KeyDerivation.deriveKey(password, new byte[KeyDerivation.MIN_SALT_LENGTH_BYTES], params)
                .getEncoded().length);
        assertEquals(32, KeyDerivation.deriveKey(password, new byte[2 * KeyDerivation.SALT_LENGTH_BYTES], params)
                .getEncoded().length);
    }

    /** The cheapest settings KdfParams allows, to keep the suite fast. */
    private static KdfParams testParams() {
        return new KdfParams(KdfParams.MIN_MEMORY_KIB, 1, 1, 32);
    }

    private static byte[] argon2(byte[] password, byte[] salt, KdfParams params) {
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(KdfParams.ARGON2_VERSION)
                .withIterations(params.iterations())
                .withMemoryAsKB(params.memoryKib())
                .withParallelism(params.parallelism())
                .withSalt(salt)
                .build());

        byte[] result = new byte[params.keyLengthBytes()];
        generator.generateBytes(password, result);

        return result;
    }
}
