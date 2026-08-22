package crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class CryptoServiceTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    public void roundTripReturnsThePlaintext() throws Exception {
        SecretKey key = key();
        byte[] plaintext = "correct horse battery staple".getBytes(StandardCharsets.UTF_8);

        assertArrayEquals(plaintext, CryptoService.decrypt(key, CryptoService.encrypt(key, plaintext)));
    }

    /** Entries hold arbitrary bytes, so nothing may assume text or a block-sized length. */
    @Test
    public void roundTripsArbitraryBytes() throws Exception {
        SecretKey key = key();
        byte[] plaintext = new byte[1024];
        RANDOM.nextBytes(plaintext);

        assertArrayEquals(plaintext, CryptoService.decrypt(key, CryptoService.encrypt(key, plaintext)));
    }

    /** An empty plaintext still authenticates: the ciphertext is the bare tag. */
    @Test
    public void roundTripsEmptyPlaintext() throws Exception {
        SecretKey key = key();

        EncryptedData encrypted = CryptoService.encrypt(key, new byte[0]);

        assertEquals(CryptoService.TAG_LENGTH_BITS / 8, encrypted.ciphertext().length);
        assertEquals(0, CryptoService.decrypt(key, encrypted).length);
    }

    @Test
    public void producesExpectedIvLengthAndAppendsTheTag() throws Exception {
        byte[] plaintext = new byte[40];

        EncryptedData encrypted = CryptoService.encrypt(key(), plaintext);

        assertEquals(CryptoService.IV_LENGTH_BYTES, encrypted.iv().length);
        assertEquals(plaintext.length + CryptoService.TAG_LENGTH_BITS / 8, encrypted.ciphertext().length);
    }

    /**
     * The property a fresh IV per call buys: encrypting the same value twice under one key must not
     * be recognisable. A cached Cipher or a reused IV would make both ciphertexts identical.
     */
    @Test
    public void sameInputTwiceProducesDifferentIvAndCiphertext() throws Exception {
        SecretKey key = key();
        byte[] plaintext = "same value".getBytes(StandardCharsets.UTF_8);

        EncryptedData first = CryptoService.encrypt(key, plaintext);
        EncryptedData second = CryptoService.encrypt(key, plaintext);

        assertFalse(Arrays.equals(first.iv(), second.iv()));
        assertFalse(Arrays.equals(first.ciphertext(), second.ciphertext()));
    }

    @Test
    public void ivIsNotAllZeros() throws Exception {
        EncryptedData encrypted = CryptoService.encrypt(key(), new byte[16]);

        assertFalse(Arrays.equals(new byte[CryptoService.IV_LENGTH_BYTES], encrypted.iv()),
                "IV must not be all zeros");
    }

    /** Guards against the plaintext being handed to the cipher unencrypted. */
    @Test
    public void ciphertextDoesNotContainThePlaintext() throws Exception {
        byte[] plaintext = "correct horse battery staple".getBytes(StandardCharsets.UTF_8);

        EncryptedData encrypted = CryptoService.encrypt(key(), plaintext);

        assertFalse(Arrays.equals(plaintext, Arrays.copyOf(encrypted.ciphertext(), plaintext.length)));
    }

    /** The caller owns the plaintext and decides when to wipe it. */
    @Test
    public void doesNotClearCallersPlaintext() throws Exception {
        byte[] plaintext = "correct horse battery staple".getBytes(StandardCharsets.UTF_8);

        CryptoService.encrypt(key(), plaintext);

        assertArrayEquals("correct horse battery staple".getBytes(StandardCharsets.UTF_8), plaintext);
    }

    /** decrypt hands out a fresh array, so wiping one result cannot damage the stored record. */
    @Test
    public void decryptReturnsAFreshArrayEveryCall() throws Exception {
        SecretKey key = key();
        byte[] plaintext = "correct horse battery staple".getBytes(StandardCharsets.UTF_8);
        EncryptedData encrypted = CryptoService.encrypt(key, plaintext);

        Arrays.fill(CryptoService.decrypt(key, encrypted), (byte) 0);

        assertArrayEquals(plaintext, CryptoService.decrypt(key, encrypted));
    }

    /** What a wrong master password looks like: the tag check fails, no plaintext is returned. */
    @Test
    public void wrongKeyFailsTheTagCheck() throws Exception {
        EncryptedData encrypted = CryptoService.encrypt(key(), "secret".getBytes(StandardCharsets.UTF_8));

        assertThrows(AEADBadTagException.class, () -> CryptoService.decrypt(key(), encrypted));
    }

    /** What GCM buys over a plain cipher: a modified vault is detected rather than decrypted to garbage. */
    @Test
    public void flippedBitInTheCiphertextFailsTheTagCheck() throws Exception {
        SecretKey key = key();
        EncryptedData encrypted = CryptoService.encrypt(key, "secret".getBytes(StandardCharsets.UTF_8));

        byte[] tampered = encrypted.ciphertext();
        tampered[0] ^= 1;

        assertThrows(AEADBadTagException.class,
                () -> CryptoService.decrypt(key, new EncryptedData(encrypted.iv(), tampered)));
    }

    /** A flipped bit in the tag itself, i.e. the last byte, must be caught too. */
    @Test
    public void flippedBitInTheTagFailsTheTagCheck() throws Exception {
        SecretKey key = key();
        EncryptedData encrypted = CryptoService.encrypt(key, "secret".getBytes(StandardCharsets.UTF_8));

        byte[] tampered = encrypted.ciphertext();
        tampered[tampered.length - 1] ^= 1;

        assertThrows(AEADBadTagException.class,
                () -> CryptoService.decrypt(key, new EncryptedData(encrypted.iv(), tampered)));
    }

    /** The IV is authenticated as well, so a damaged iv column cannot be papered over. */
    @Test
    public void flippedBitInTheIvFailsTheTagCheck() throws Exception {
        SecretKey key = key();
        EncryptedData encrypted = CryptoService.encrypt(key, "secret".getBytes(StandardCharsets.UTF_8));

        byte[] tampered = encrypted.iv();
        tampered[0] ^= 1;

        assertThrows(AEADBadTagException.class,
                () -> CryptoService.decrypt(key, new EncryptedData(tampered, encrypted.ciphertext())));
    }

    /** Two records must not be decryptable with each other's IV. */
    @Test
    public void ivFromAnotherRecordFailsTheTagCheck() throws Exception {
        SecretKey key = key();
        EncryptedData first = CryptoService.encrypt(key, "secret".getBytes(StandardCharsets.UTF_8));
        EncryptedData second = CryptoService.encrypt(key, "secret".getBytes(StandardCharsets.UTF_8));

        assertThrows(AEADBadTagException.class,
                () -> CryptoService.decrypt(key, new EncryptedData(second.iv(), first.ciphertext())));
    }

    @Test
    public void rejectsMissingEncryptedData() {
        SecretKey key = key();

        assertThrows(IllegalArgumentException.class, () -> CryptoService.decrypt(key, null));
    }

    /** A key of the wrong length surfaces as a GeneralSecurityException, as the javadoc promises. */
    @Test
    public void rejectsKeyUnusableForAesGcm() {
        SecretKey tooShort = new SecretKeySpec(new byte[7], "AES");

        assertThrows(GeneralSecurityException.class,
                () -> CryptoService.encrypt(tooShort, "secret".getBytes(StandardCharsets.UTF_8)));
    }

    /** Both AES key sizes the vault could be configured for, per KdfParams.keyLengthBytes(). */
    @Test
    public void worksWithAes128AndAes256() throws Exception {
        byte[] plaintext = "secret".getBytes(StandardCharsets.UTF_8);

        for (int keyLength : new int[]{16, 32}) {
            byte[] material = new byte[keyLength];
            RANDOM.nextBytes(material);
            SecretKey key = new SecretKeySpec(material, "AES");

            assertArrayEquals(plaintext, CryptoService.decrypt(key, CryptoService.encrypt(key, plaintext)));
        }
    }

    /**
     * The path the vault actually takes: the two arrays go into separate columns and come back as a
     * rebuilt record, so decrypt must not depend on being handed the instance encrypt returned.
     */
    @Test
    public void decryptsARecordRebuiltFromStoredColumns() throws Exception {
        SecretKey key = key();
        byte[] plaintext = "secret".getBytes(StandardCharsets.UTF_8);

        EncryptedData encrypted = CryptoService.encrypt(key, plaintext);
        EncryptedData readBack = new EncryptedData(encrypted.iv().clone(), encrypted.ciphertext().clone());

        assertArrayEquals(plaintext, CryptoService.decrypt(key, readBack));
    }

    private static SecretKey key() {
        byte[] material = new byte[32];
        RANDOM.nextBytes(material);

        return new SecretKeySpec(material, "AES");
    }
}
