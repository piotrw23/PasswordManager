package crypto;

/**
 * Argon2id cost parameters. Stored next to the vault so a vault created with older, cheaper
 * settings can still be opened after the defaults are raised.
 *
 * @param memoryKib      memory cost in KiB
 * @param iterations     number of passes over memory
 * @param parallelism    number of lanes
 * @param keyLengthBytes length of the derived key (32 for AES-256)
 */
public record KdfParams(int memoryKib, int iterations, int parallelism, int keyLengthBytes) {

    public static final int ARGON2_VERSION = 0x13;
    public static final int MIN_MEMORY_KIB = 8 * 1024;

    private static final String ALGORITHM = "argon2id";


    public KdfParams {
        if(memoryKib < MIN_MEMORY_KIB) throw new IllegalArgumentException("MemoryKib value must be at least " + MIN_MEMORY_KIB);
        if(iterations < 1) throw new IllegalArgumentException("Invalid iterations value");
        if(parallelism < 1) throw new IllegalArgumentException("Invalid parallelism value");
        if(keyLengthBytes < 32) throw new IllegalArgumentException("KeyLengthBytes value must be at least 32");
    }

    /**
     * Cost settings used when a new vault is created.
     */
    public static KdfParams defaults() {
        return new KdfParams(64 * 1024, 3, 1, 32);
    }

    /**
     * Encodes the parameters for storage, e.g. {@code argon2id$v=19$m=65536,t=3,p=1,k=32}.
     */
    public String encode() {
        return ALGORITHM + "$v=" + ARGON2_VERSION + "$m=" + memoryKib
                + ",t=" + iterations + ",p=" + parallelism + ",k=" + keyLengthBytes;
    }

    /**
     * Reads back what {@link #encode()} produced.
     *
     * @throws IllegalArgumentException when the text is malformed, names a different algorithm
     *                                  or an unsupported Argon2 version
     */
    public static KdfParams parse(String encoded) {
        if (encoded == null) {
            throw new IllegalArgumentException("Missing KDF parameters");
        }

        // argon2id $ v=19 $ m=65536,t=3,p=1,k=32
        String[] sections = encoded.trim().split("\\$");
        if (sections.length != 3) {
            throw new IllegalArgumentException("Malformed KDF parameters: " + encoded);
        }

        if (!ALGORITHM.equals(sections[0])) {
            throw new IllegalArgumentException("Unsupported KDF algorithm: " + sections[0]);
        }

        int version = readField(sections[1], "v");
        if (version != ARGON2_VERSION) {
            throw new IllegalArgumentException("Unsupported Argon2 version: " + version);
        }

        String[] costs = sections[2].split(",");
        if (costs.length != 4) {
            throw new IllegalArgumentException("Expected m, t, p and k in KDF parameters: " + sections[2]);
        }

        // the record's constructor rejects values that are too weak to protect the vault
        return new KdfParams(
                readField(costs[0], "m"),
                readField(costs[1], "t"),
                readField(costs[2], "p"),
                readField(costs[3], "k"));
    }

    private static int readField(String field, String name) {
        String prefix = name + "=";
        if (!field.startsWith(prefix)) {
            throw new IllegalArgumentException("Expected " + prefix + " in KDF parameters, got: " + field);
        }

        try {
            return Integer.parseInt(field.substring(prefix.length()));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Value of " + name + " is not a number: " + field, e);
        }
    }
}
