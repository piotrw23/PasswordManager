package crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class KdfParamsTest {

    @Test
    public void parsesWellFormedInput() {
        assertEquals(new KdfParams(64 * 1024, 3, 1, 32),
                KdfParams.parse("argon2id$v=19$m=65536,t=3,p=1,k=32"));
    }

    @Test
    public void rejectsInvalidKdfParams() {
        assertThrows(IllegalArgumentException.class, () -> KdfParams.parse(null));
        assertThrows(IllegalArgumentException.class, () -> KdfParams.parse(""));
        assertThrows(IllegalArgumentException.class, () -> KdfParams.parse("scrypt$v=19$m=65536,t=3,p=1,k=32"));
        assertThrows(IllegalArgumentException.class, () -> KdfParams.parse("argon2id$v=16$m=65536,t=3,p=1,k=32"));
        assertThrows(IllegalArgumentException.class, () -> KdfParams.parse("argon2id$v=19$m=65536,t=3,p=1"));
        assertThrows(IllegalArgumentException.class, () -> KdfParams.parse("argon2id$v=19$m=65536,3,1,32"));
        assertThrows(IllegalArgumentException.class, () -> KdfParams.parse("argon2id$v=19$m=abc,t=3,p=1,k=32"));
        assertThrows(IllegalArgumentException.class, () -> KdfParams.parse("argon2id$v=19$m=1024,t=3,p=1,k=32"));
    }

    @Test
    public void encodeKdfParams() {
        assertEquals("argon2id$v=19$m=65536,t=3,p=1,k=32",
                new KdfParams(64 * 1024, 3, 1, 32).encode());

        assertEquals("argon2id$v=19$m=65536,t=3,p=1,k=32",
                 KdfParams.defaults().encode());
    }

}
