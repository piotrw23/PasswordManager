package core;

import crypto.CryptoService;
import crypto.EncryptedData;
import crypto.KdfParams;
import crypto.KeyDerivation;
import storage.SchemaInitializer;
import storage.VaultDatabase;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;

/**
 * Creates a new vault: the database, its schema and the metadata needed to open it again.
 *
 * <p>Deliberately free of any CLI concern. It neither prompts for a password nor prints anything,
 * so the whole creation sequence can be tested against a temporary directory without a terminal.
 * {@code InitCommand} reads the password, confirms {@code --force} and turns failures into exit
 * codes; everything below that line lives here.
 *
 * <p>The sequence is:
 * <ol>
 *   <li>refuse to run when a vault is already there
 *   <li>draw a random salt and derive the master key from the password with Argon2id
 *   <li>draw a random data encryption key (DEK) and wrap it under the master key
 *   <li>encrypt the canary, so a wrong password can be reported instead of surfacing as
 *       corrupt-looking output later
 *   <li>create the database and write every metadata row in one transaction
 * </ol>
 *
 * <p><strong>Why a DEK at all:</strong> entries are encrypted under the DEK, not under the key
 * derived from the password. Changing the master password then only rewraps the DEK, instead of
 * re-encrypting every entry in the vault.
 *
 * <p><strong>Ownership of the password:</strong> the {@code char[]} handed in is read, never
 * cleared — the caller owns it and is responsible for wiping it in a {@code finally} block.
 *
 * <p>Every byte array this class creates is cleared once it has been used, but the keys themselves
 * cannot be: {@link SecretKeySpec} keeps a private copy of its material and its {@code destroy()}
 * throws {@link javax.security.auth.DestroyFailedException}, so the master key and the DEK stay in
 * the heap until the collector takes them. That is a limit of the JDK's {@link SecretKey}
 * implementations rather than something a caller can work around.
 */
public final class VaultInitializer {

    /** Bumped whenever the schema changes in a way an older build could not read. */
    static final int CURRENT_SCHEMA_VERSION = 1;

    /** AES-256, matching the key length Argon2id is asked for in {@link KdfParams}. */
    static final int DEK_LENGTH_BYTES = 32;

    /**
     * Plaintext of the canary. Its content is not secret and does not need to be unguessable: the
     * point is only that decrypting it with the wrong key fails the GCM tag check.
     */
    static final String CANARY_PLAINTEXT = "pass-mgr canary";

    // vault_meta keys
    static final String KEY_SCHEMA_VERSION = "schema_version";
    static final String KEY_KDF_PARAMS = "kdf_params";
    static final String KEY_KDF_SALT = "kdf_salt";
    static final String KEY_WRAPPED_DEK_IV = "wrapped_dek_iv";
    static final String KEY_WRAPPED_DEK = "wrapped_dek";
    static final String KEY_VERIFIER_IV = "verifier_iv";
    static final String KEY_VERIFIER_CT = "verifier_ct";
    static final String KEY_CREATED_AT = "created_at";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /** Suffix of the file a vault is built under before it is moved into place. */
    private static final String TEMPORARY_SUFFIX = ".tmp";

    /**
     * A SQLite database is up to three files. Cleaning up after a failed run has to remove all of
     * them: a stray {@code -wal} left next to a fresh database would be replayed into it.
     */
    private static final List<String> DATABASE_FILE_SUFFIXES = List.of("", "-wal", "-shm");

    private static final String INSERT_META = "INSERT INTO vault_meta(key, value) VALUES (?, ?)";

    private final VaultPaths paths;
    private final KdfParams kdfParams;

    public VaultInitializer(VaultPaths paths) {
        this(paths, KdfParams.defaults());
    }

    /**
     * Kept package-private so tests can create vaults with the cheapest Argon2id settings the
     * parameters allow. The real defaults take a noticeable fraction of a second by design, which
     * is fine once per {@code init} and far too slow for a test suite that creates many vaults.
     */
    VaultInitializer(VaultPaths paths, KdfParams kdfParams) {
        this.paths = paths;
        this.kdfParams = kdfParams;
    }

    /**
     * Creates a vault at {@link VaultPaths#databaseFile()} protected by {@code masterPassword}.
     *
     * <p>The vault is built under a temporary file and moved into place only once it is complete,
     * so an interrupted run never leaves something at the real path that the next run would mistake
     * for an existing vault.
     *
     * @param masterPassword read but not cleared; the caller owns it
     * @throws IllegalStateException if a vault already exists
     */
    public void initialize(char[] masterPassword) throws IOException, SQLException, GeneralSecurityException {
        // checked before the directory is touched, so refusing leaves the filesystem as it was
        if (paths.vaultExists()) {
            throw new IllegalStateException("A vault already exists at " + paths.databaseFile());
        }
        paths.ensureVaultDirectory();

        // the salt is not a secret and is stored in the clear next to the vault; what it buys is
        // that two vaults with the same password derive different keys, so one cracked password
        // does not carry over and no precomputed table applies
        byte[] salt = KeyDerivation.generateSalt();
        SecretKey masterKey = KeyDerivation.deriveKey(masterPassword, salt, kdfParams);

        // entries are encrypted under the DEK, so changing the master password later only has to
        // rewrap these few bytes instead of re-encrypting every entry in the vault
        SecretKey dek = generateDek();
        byte[] dekMaterial = dek.getEncoded();
        EncryptedData wrappedDek;
        try {
            wrappedDek = CryptoService.encrypt(masterKey, dekMaterial);
        } finally {
            // getEncoded() hands out a copy, and this one has served its purpose
            Arrays.fill(dekMaterial, (byte) 0);
        }

        // encrypted under the DEK rather than the master key, so decrypting it proves the whole
        // chain: password, master key, unwrapped DEK. Under the master key it would only repeat
        // the tag check that unwrapping the DEK already performs
        EncryptedData canary = CryptoService.encrypt(dek, CANARY_PLAINTEXT.getBytes(StandardCharsets.UTF_8));

        Path target = paths.databaseFile();
        Path temporary = target.resolveSibling(target.getFileName() + TEMPORARY_SUFFIX);

        // a run that died before the move leaves this behind; opening a stale database would fail
        // further in with "table already exists", which says nothing about what actually happened
        deleteDatabaseFiles(temporary);

        try {
            try (VaultDatabase vault = VaultDatabase.open(temporary)) {
                // one transaction: a database holding tables but no metadata could never be
                // opened, and SQLite rolls back CREATE TABLE along with everything else
                vault.inTransaction(connection -> {
                    SchemaInitializer.createSchema(connection);
                    writeMetadata(connection, salt, wrappedDek, canary);
                    return null;
                });
            }

            // the vault is closed by now, so its WAL has been checkpointed into the file being
            // moved; ATOMIC_MOVE then puts a complete vault at the target path in one step
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException | SQLException | RuntimeException e) {
            deleteQuietly(temporary, e);
            throw e;
        }
    }

    /**
     * Draws a fresh data encryption key from {@link java.security.SecureRandom}.
     *
     * <p>Only the key is returned. The bytes needed to wrap it come back from
     * {@link SecretKey#getEncoded()}, which hands out a fresh copy the caller can clear, so the
     * array created here never has to outlive this method.
     */
    private static SecretKey generateDek() {
        byte[] material = new byte[DEK_LENGTH_BYTES];
        try {
            SECURE_RANDOM.nextBytes(material);
            // SecretKeySpec copies what it is given, so clearing the original is safe
            return new SecretKeySpec(material, "AES");
        } finally {
            Arrays.fill(material, (byte) 0);
        }
    }

    /**
     * Writes every {@code vault_meta} row for a freshly created vault.
     *
     * <p>The {@code value} column is {@code ANY}, so every row goes in with the type it naturally
     * has and comes back out the same way — no encoding to agree on, and the table stays readable
     * with {@code sqlite3}.
     *
     * <p>Both halves of an {@link EncryptedData} are stored: a ciphertext without its IV cannot be
     * decrypted, so {@code wrapped_dek} and the canary each need two rows.
     *
     * <p>Runs inside the caller's transaction and neither commits nor rolls back.
     */
    private void writeMetadata(Connection connection, byte[] salt, EncryptedData wrappedDek,
                               EncryptedData canary) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(INSERT_META)) {
            putNumber(statement, KEY_SCHEMA_VERSION, CURRENT_SCHEMA_VERSION);
            putText(statement, KEY_KDF_PARAMS, kdfParams.encode());
            putBytes(statement, KEY_KDF_SALT, salt);
            putBytes(statement, KEY_WRAPPED_DEK_IV, wrappedDek.iv());
            putBytes(statement, KEY_WRAPPED_DEK, wrappedDek.ciphertext());
            putBytes(statement, KEY_VERIFIER_IV, canary.iv());
            putBytes(statement, KEY_VERIFIER_CT, canary.ciphertext());
            putNumber(statement, KEY_CREATED_AT, System.currentTimeMillis());

            statement.executeBatch();
        }
    }

    /** SQLite has one integer type, so the schema version and the timestamp are written the same way. */
    private static void putNumber(PreparedStatement statement, String key, long value) throws SQLException {
        statement.setString(1, key);
        statement.setLong(2, value);
        statement.addBatch();
    }

    private static void putText(PreparedStatement statement, String key, String value) throws SQLException {
        statement.setString(1, key);
        statement.setString(2, value);
        statement.addBatch();
    }

    private static void putBytes(PreparedStatement statement, String key, byte[] value) throws SQLException {
        statement.setString(1, key);
        statement.setBytes(2, value);
        statement.addBatch();
    }

    /**
     * Removes a database and the side files SQLite keeps beside it.
     *
     * <p>Used before building a vault, where a leftover from an interrupted run has to go, and
     * again when that build fails.
     */
    private static void deleteDatabaseFiles(Path database) throws IOException {
        for (String suffix : DATABASE_FILE_SUFFIXES) {
            Files.deleteIfExists(database.resolveSibling(database.getFileName() + suffix));
        }
    }

    /**
     * Cleans up after a failed run, reporting any problem as a suppressed exception on
     * {@code primary} — what stopped the vault from being created matters more than what stopped
     * its leftovers from being removed.
     */
    private static void deleteQuietly(Path database, Throwable primary) {
        try {
            deleteDatabaseFiles(database);
        } catch (IOException cleanupFailure) {
            primary.addSuppressed(cleanupFailure);
        }
    }
}
