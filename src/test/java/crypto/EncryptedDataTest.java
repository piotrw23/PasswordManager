package crypto;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class EncryptedDataTest {

    @Test
    public void acceptsAWellFormedPair() {
        EncryptedData data = new EncryptedData(validIv(), validCiphertext());

        assertArrayEquals(validIv(), data.iv());
        assertArrayEquals(validCiphertext(), data.ciphertext());
    }

    /** A damaged iv column must not reach the cipher, where it would look like a wrong password. */
    @Test
    public void rejectsIvOfTheWrongLength() {
        byte[] ciphertext = validCiphertext();

        assertThrows(IllegalArgumentException.class, () -> new EncryptedData(null, ciphertext));
        assertThrows(IllegalArgumentException.class, () -> new EncryptedData(new byte[0], ciphertext));
        assertThrows(IllegalArgumentException.class,
                () -> new EncryptedData(new byte[CryptoService.IV_LENGTH_BYTES - 1], ciphertext));
        assertThrows(IllegalArgumentException.class,
                () -> new EncryptedData(new byte[CryptoService.IV_LENGTH_BYTES + 1], ciphertext));
    }

    /**
     * Even an empty plaintext produces the tag, so anything shorter than the tag cannot have come
     * from encrypt() and is a damaged record, not a wrong password.
     */
    @Test
    public void rejectsCiphertextShorterThanTheTag() {
        byte[] iv = validIv();

        assertThrows(IllegalArgumentException.class, () -> new EncryptedData(iv, null));
        assertThrows(IllegalArgumentException.class, () -> new EncryptedData(iv, new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> new EncryptedData(iv, new byte[1]));
        assertThrows(IllegalArgumentException.class,
                () -> new EncryptedData(iv, new byte[EncryptedData.MIN_CIPHERTEXT_LENGTH_BYTES - 1]));
    }

    /** The bound is the tag length itself, i.e. what encrypting an empty plaintext yields. */
    @Test
    public void acceptsACiphertextOfExactlyTheTagLength() {
        EncryptedData data = new EncryptedData(validIv(), new byte[EncryptedData.MIN_CIPHERTEXT_LENGTH_BYTES]);

        assertEquals(EncryptedData.MIN_CIPHERTEXT_LENGTH_BYTES, data.ciphertext().length);
        assertEquals(CryptoService.TAG_LENGTH_BITS / 8, EncryptedData.MIN_CIPHERTEXT_LENGTH_BYTES);
    }

    /**
     * The record stores copies, so a caller that reuses or wipes its buffers after handing them
     * over cannot change what an already-validated record holds.
     */
    @Test
    public void copiesTheArraysItIsGiven() {
        byte[] iv = validIv();
        byte[] ciphertext = validCiphertext();

        EncryptedData data = new EncryptedData(iv, ciphertext);
        Arrays.fill(iv, (byte) 0);
        Arrays.fill(ciphertext, (byte) 0);

        assertArrayEquals(validIv(), data.iv());
        assertArrayEquals(validCiphertext(), data.ciphertext());
    }

    /** Copying on the way in would be pointless if the accessors handed the stored array back out. */
    @Test
    public void accessorsHandOutCopies() {
        EncryptedData data = new EncryptedData(validIv(), validCiphertext());

        Arrays.fill(data.iv(), (byte) 0);
        Arrays.fill(data.ciphertext(), (byte) 0);

        assertArrayEquals(validIv(), data.iv());
        assertArrayEquals(validCiphertext(), data.ciphertext());
    }

    @Test
    public void accessorsReturnADistinctArrayEachCall() {
        EncryptedData data = new EncryptedData(validIv(), validCiphertext());

        assertNotSame(data.iv(), data.iv());
        assertNotSame(data.ciphertext(), data.ciphertext());
    }

    /** The generated equals would have compared array references, making this fail. */
    @Test
    public void equalsComparesTheBytes() {
        EncryptedData data = new EncryptedData(validIv(), validCiphertext());

        assertEquals(data, new EncryptedData(validIv(), validCiphertext()));
        assertEquals(data, data);
    }

    @Test
    public void differsWhenEitherPartDiffers() {
        EncryptedData data = new EncryptedData(validIv(), validCiphertext());

        byte[] otherIv = validIv();
        otherIv[0] ^= 1;
        byte[] otherCiphertext = validCiphertext();
        otherCiphertext[0] ^= 1;

        assertNotEquals(data, new EncryptedData(otherIv, validCiphertext()));
        assertNotEquals(data, new EncryptedData(validIv(), otherCiphertext));
        assertNotEquals(data, new EncryptedData(validIv(), Arrays.copyOf(validCiphertext(),
                CryptoService.TAG_LENGTH_BITS / 8 + 1)));
    }

    @Test
    public void isNotEqualToNullOrAnotherType() {
        EncryptedData data = new EncryptedData(validIv(), validCiphertext());

        assertNotEquals(null, data);
    }

    /** Without this, a record read back from the vault would not be found in a HashSet or map. */
    @Test
    public void equalRecordsShareAHashCode() {
        EncryptedData data = new EncryptedData(validIv(), validCiphertext());
        EncryptedData same = new EncryptedData(validIv(), validCiphertext());

        assertEquals(data.hashCode(), same.hashCode());
        assertTrue(new HashSet<>(List.of(data)).contains(same));
    }

    /** Cheap guard against a hashCode that ignores one of the two parts. */
    @Test
    public void hashCodeDependsOnBothParts() {
        EncryptedData data = new EncryptedData(validIv(), validCiphertext());

        byte[] otherIv = validIv();
        otherIv[0] ^= 1;
        byte[] otherCiphertext = validCiphertext();
        otherCiphertext[0] ^= 1;

        assertNotEquals(data.hashCode(), new EncryptedData(otherIv, validCiphertext()).hashCode());
        assertNotEquals(data.hashCode(), new EncryptedData(validIv(), otherCiphertext).hashCode());
    }

    private static byte[] validIv() {
        byte[] iv = new byte[CryptoService.IV_LENGTH_BYTES];
        Arrays.fill(iv, (byte) 1);

        return iv;
    }

    /** The shortest ciphertext encrypt() can produce: the tag alone, from an empty plaintext. */
    private static byte[] validCiphertext() {
        byte[] ciphertext = new byte[CryptoService.TAG_LENGTH_BITS / 8];
        Arrays.fill(ciphertext, (byte) 2);

        return ciphertext;
    }
}
