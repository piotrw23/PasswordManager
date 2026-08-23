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
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

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
 *   <li>claim the real path, which at most one run can do
 * </ol>
 *
 * <p><strong>Two runs at once:</strong> the vault is built under a name no other run can be using
 * and only then claimed at its real path, by a filesystem operation that fails when something is
 * already there. Two {@code init} runs started at the same moment therefore end with one vault and
 * one refusal, whichever order they happen to run in. The check at the top of {@link #initialize}
 * is only there to fail early and cheaply; it is the claim that decides.
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

    /**
     * A vault is built under {@code vault-<random>.db.tmp} and claimed at its real path afterwards.
     * The name is unique per run: two runs sharing one would overwrite each other's database as
     * they built it, and the one that finished second could be claimed while still half written.
     *
     * <p>Kept package-private, like the glob below, so tests can put a leftover where a run that
     * died would have left one.
     */
    static final String TEMPORARY_PREFIX = "vault-";

    static final String TEMPORARY_SUFFIX = ".db.tmp";

    /** Matches every name {@link #createTemporaryFile} can produce, side files included. */
    static final String TEMPORARY_GLOB = TEMPORARY_PREFIX + "*" + TEMPORARY_SUFFIX + "*";

    /**
     * A half-built vault is still a vault: it holds the wrapped DEK and the salt, so it must be no
     * more readable than the finished one. The permissions are passed to
     * {@link Files#createTempFile} as an attribute, so the file is never briefly readable by others.
     */
    private static final FileAttribute<Set<PosixFilePermission>> OWNER_ONLY_FILE =
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"));

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
     * <p>The vault is built under a temporary file and claimed at the real path only once it is
     * complete, so an interrupted run never leaves something at the real path that the next run
     * would mistake for an existing vault.
     *
     * @param masterPassword read but not cleared; the caller owns it
     * @throws IllegalStateException if a vault already exists, including one that appeared while
     *                               this run was building its own
     */
    public void initialize(char[] masterPassword) throws IOException, SQLException, GeneralSecurityException {
        // checked before the directory is touched, so refusing leaves the filesystem as it was.
        // Only an early exit: a vault created from here on is caught by the claim at the end, which
        // is what actually keeps two runs from overwriting each other
        if (paths.vaultExists()) {
            throw new IllegalStateException(alreadyExistsMessage(paths.databaseFile()));
        }
        paths.ensureVaultDirectory();

        // before the expensive part, and while this run still has no file of its own to confuse
        // with someone else's
        deleteStaleTemporaryFiles();

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
        Path temporary = createTemporaryFile();

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
            // claimed, and what appears at the target path is a complete vault
            claim(target, temporary);
        } catch (IOException | SQLException | RuntimeException e) {
            deleteQuietly(temporary, e);
            throw e;
        }

        // both names refer to the finished vault; the temporary one has served its purpose. A
        // failure here would leave the vault in place, so reporting one would be a lie — and the
        // leftover is swept up by the next run
        deleteQuietly(temporary);
    }

    /**
     * Puts the finished vault at its real path, atomically, and only when nothing is there.
     *
     * <p>A hard link rather than a move: {@link Files#move} replaces whatever it finds, so of two
     * runs racing each other both would report success and the loser's vault would be gone without
     * a word — including every secret in it, if the loser was the older vault. Linking fails when
     * the target exists, and the filesystem decides that for the whole operation, so at most one
     * run can win no matter how the two interleave.
     *
     * <p>Afterwards both names refer to one file; the caller removes the temporary one.
     *
     * <p>Kept package-private so tests can exercise both outcomes of the race directly, rather than
     * by starting threads and hoping they interleave the interesting way.
     *
     * @throws IllegalStateException if a vault is already at {@code target}
     * @throws IOException           if something that is not a vault is in the way, or the link
     *                               cannot be created
     */
    static void claim(Path target, Path temporary) throws IOException {
        try {
            Files.createLink(target, temporary);
        } catch (FileAlreadyExistsException e) {
            // the path is taken either way and this run has lost; the second look only decides the
            // wording, so a further change underneath it costs nothing
            if (Files.isRegularFile(target)) {
                throw new IllegalStateException(alreadyExistsMessage(target), e);
            }
            throw e;
        }
    }

    /**
     * Creates the file the vault is built under, with a name no other run can be using.
     *
     * <p>{@link Files#createTempFile} both draws the name and creates the file in one step, so two
     * runs cannot come away with the same one. An empty file is a valid empty database, which is
     * what lets the name be claimed by creating it rather than by hoping it is free.
     */
    private Path createTemporaryFile() throws IOException {
        return Files.createTempFile(paths.vaultHome(), TEMPORARY_PREFIX, TEMPORARY_SUFFIX, OWNER_ONLY_FILE);
    }

    /**
     * Removes what runs that died before claiming their vault left behind.
     *
     * <p>Names are unique per run, so nothing else would ever collect these, and each holds a
     * wrapped DEK the user's password unwraps — the same thing worth stealing as the vault itself.
     *
     * <p>Runs before this run creates a file of its own, so it never sweeps away its own work.
     *
     * <p>Deleting one that a run started moments ago is still building costs that run its file and
     * makes it fail when it goes to claim it. It cannot produce a damaged vault: the name it links
     * from is one no other run can recreate, so the link either finds the file this run built or
     * finds nothing at all. That window is only as long as it takes to write the database — the
     * key derivation, which is the slow part, happens before the file exists.
     */
    private void deleteStaleTemporaryFiles() throws IOException {
        List<Path> leftovers = new ArrayList<>();
        try (DirectoryStream<Path> entries =
                     Files.newDirectoryStream(paths.vaultHome(), TEMPORARY_GLOB)) {
            entries.forEach(leftovers::add);
        }

        for (Path leftover : leftovers) {
            Files.deleteIfExists(leftover);
        }
    }

    private static String alreadyExistsMessage(Path databaseFile) {
        return "A vault already exists at " + databaseFile;
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
     * <p>Used to remove the file a run built under, whether that run failed or succeeded.
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

    /**
     * Cleans up after a run that succeeded. There is no failure to report against here: the vault
     * exists, so the run did what it was asked. A leftover is collected by the next run.
     */
    private static void deleteQuietly(Path database) {
        try {
            deleteDatabaseFiles(database);
        } catch (IOException ignored) {
            // deliberately ignored; see above
        }
    }
}
