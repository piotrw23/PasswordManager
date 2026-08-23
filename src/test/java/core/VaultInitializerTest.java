package core;

import crypto.CryptoService;
import crypto.EncryptedData;
import crypto.KdfParams;
import crypto.KeyDerivation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import storage.VaultDatabase;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static core.VaultInitializer.CANARY_PLAINTEXT;
import static core.VaultInitializer.CURRENT_SCHEMA_VERSION;
import static core.VaultInitializer.DEK_LENGTH_BYTES;
import static core.VaultInitializer.KEY_CREATED_AT;
import static core.VaultInitializer.KEY_KDF_PARAMS;
import static core.VaultInitializer.KEY_KDF_SALT;
import static core.VaultInitializer.KEY_SCHEMA_VERSION;
import static core.VaultInitializer.KEY_VERIFIER_CT;
import static core.VaultInitializer.KEY_VERIFIER_IV;
import static core.VaultInitializer.KEY_WRAPPED_DEK;
import static core.VaultInitializer.KEY_WRAPPED_DEK_IV;
import static core.VaultInitializer.TEMPORARY_PREFIX;
import static core.VaultInitializer.TEMPORARY_SUFFIX;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

/**
 * The vault is created exactly once and can never be recreated, so a mistake here is unrecoverable:
 * a missing metadata row locks the user out for good, and a reused IV or a plaintext left in the
 * file leaks the secrets the vault exists to protect. These tests therefore go past the happy path
 * and check the guarantees the class claims — crash safety, cleanup, and what the bytes on disk
 * actually contain.
 */
class VaultInitializerTest {

    /**
     * The cheapest settings {@link KdfParams} accepts. The real defaults are deliberately slow,
     * which is right once per {@code init} and unusable in a suite that creates a vault per test.
     */
    private static final KdfParams TEST_PARAMS = new KdfParams(KdfParams.MIN_MEMORY_KIB, 1, 1, 32);

    private static final char[] PASSWORD = "correct horse battery staple".toCharArray();
    private static final char[] WRONG_PASSWORD = "correct horse battery stapl3".toCharArray();

    private static final String DATABASE_NAME = "vault.db";

    /** A name matching the one a run builds under, for planting what a dead run would have left. */
    private static final String LEFTOVER_NAME = TEMPORARY_PREFIX + "12345678" + TEMPORARY_SUFFIX;

    /** GCM appends a 128-bit tag to every ciphertext. */
    private static final int TAG_LENGTH_BYTES = CryptoService.TAG_LENGTH_BITS / 8;

    // ---------------------------------------------------------------- what ends up on disk

    @Test
    void createsTheVaultDatabaseAtTheConfiguredPath(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        assertTrue(Files.isRegularFile(paths.databaseFile()));
        assertTrue(paths.vaultExists());
    }

    @Test
    void createsTheVaultDirectoryWhenItIsMissing(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);
        assertFalse(Files.exists(paths.vaultHome()));

        initializer(paths).initialize(PASSWORD);

        assertTrue(Files.isDirectory(paths.vaultHome()));
        assertEquals("rwx------", permissionsOf(paths.vaultHome()));
    }

    @Test
    void worksWhenTheVaultDirectoryIsAlreadyThere(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);
        paths.ensureVaultDirectory();

        initializer(paths).initialize(PASSWORD);

        assertTrue(paths.vaultExists());
        assertTrue(paths.hasSecurePermissions());
    }

    /** The directory is the main barrier, but a world-readable database file would defeat it. */
    @Test
    void leavesTheDatabaseFileReadableOnlyByItsOwner(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        assertEquals("rw-------", permissionsOf(paths.databaseFile()));
    }

    /**
     * The temporary file has served its purpose once the vault is in place. A leftover would be
     * deleted by the next run anyway, but it is a second copy of the same secrets on disk.
     */
    @Test
    void leavesNothingBehindButTheVault(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        assertEquals(List.of(DATABASE_NAME), fileNamesIn(paths.vaultHome()));
    }

    @Test
    void createsTheFullSchema(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        assertEquals(List.of("entries", "vault_meta"), tableNames(paths.databaseFile()));
    }

    @Test
    void createsAnEmptyEntriesTable(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        assertEquals(0, countRows(paths.databaseFile(), "entries"));
    }

    // ---------------------------------------------------------------- the metadata rows

    /**
     * Every row here is needed to open the vault again, and there is no second chance to write a
     * missing one. An extra row is just as much of a defect: it means a key was written that
     * nothing reads back.
     */
    @Test
    void writesExactlyTheMetadataNeededToOpenTheVault(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        assertEquals(
                Set.of(KEY_SCHEMA_VERSION, KEY_KDF_PARAMS, KEY_KDF_SALT, KEY_WRAPPED_DEK_IV,
                        KEY_WRAPPED_DEK, KEY_VERIFIER_IV, KEY_VERIFIER_CT, KEY_CREATED_AT),
                readMeta(paths).values().keySet());
    }

    /**
     * The {@code value} column is {@code ANY}, so nothing in the schema stops a row from going in
     * as the wrong kind. A salt stored as text would come back out unusable.
     */
    @Test
    void storesEveryRowWithTheTypeItNaturallyHas(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        assertEquals(
                Map.of(KEY_SCHEMA_VERSION, "integer",
                        KEY_CREATED_AT, "integer",
                        KEY_KDF_PARAMS, "text",
                        KEY_KDF_SALT, "blob",
                        KEY_WRAPPED_DEK_IV, "blob",
                        KEY_WRAPPED_DEK, "blob",
                        KEY_VERIFIER_IV, "blob",
                        KEY_VERIFIER_CT, "blob"),
                readMeta(paths).types());
    }

    @Test
    void stampsTheCurrentSchemaVersion(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        assertEquals(CURRENT_SCHEMA_VERSION, readMeta(paths).number(KEY_SCHEMA_VERSION));
    }

    @Test
    void stampsTheCreationTime(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        long before = System.currentTimeMillis();
        initializer(paths).initialize(PASSWORD);
        long after = System.currentTimeMillis();

        long createdAt = readMeta(paths).number(KEY_CREATED_AT);
        assertTrue(createdAt >= before && createdAt <= after,
                "created_at " + createdAt + " outside [" + before + ", " + after + "]");
    }

    /**
     * The parameters are what makes an old vault openable after the defaults are raised. They have
     * to survive the round trip through the database exactly.
     */
    @Test
    void storesTheKdfParametersItActuallyUsed(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        assertEquals(TEST_PARAMS, KdfParams.parse(readMeta(paths).text(KEY_KDF_PARAMS)));
    }

    /** The public constructor is what {@code init} uses, and it must record the real defaults. */
    @Test
    void storesTheDefaultParametersWhenNoneAreGiven(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        new VaultInitializer(paths).initialize(PASSWORD);

        assertEquals(KdfParams.defaults(), KdfParams.parse(readMeta(paths).text(KEY_KDF_PARAMS)));
    }

    @Test
    void storesASaltOfTheGeneratedLength(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        assertEquals(KeyDerivation.SALT_LENGTH_BYTES, readMeta(paths).bytes(KEY_KDF_SALT).length);
    }

    /**
     * A ciphertext of the wrong length means something other than what was meant got encrypted.
     * The DEK is 32 bytes and the canary 15, each plus the GCM tag.
     */
    @Test
    void storesCiphertextsOfTheExpectedLength(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        Meta meta = readMeta(paths);
        assertEquals(CryptoService.IV_LENGTH_BYTES, meta.bytes(KEY_WRAPPED_DEK_IV).length);
        assertEquals(CryptoService.IV_LENGTH_BYTES, meta.bytes(KEY_VERIFIER_IV).length);
        assertEquals(DEK_LENGTH_BYTES + TAG_LENGTH_BYTES, meta.bytes(KEY_WRAPPED_DEK).length);
        assertEquals(CANARY_PLAINTEXT.getBytes(StandardCharsets.UTF_8).length + TAG_LENGTH_BYTES,
                meta.bytes(KEY_VERIFIER_CT).length);
    }

    // ---------------------------------------------------------------- the cryptographic chain

    /** The whole point: the password given here has to lead back to the DEK. */
    @Test
    void producesAWrappedDekThatTheMasterPasswordUnwraps(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        byte[] dek = unwrapDek(readMeta(paths), PASSWORD);
        assertEquals(DEK_LENGTH_BYTES, dek.length);
    }

    @Test
    void producesACanaryThatDecryptsUnderTheDek(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        Meta meta = readMeta(paths);
        byte[] plaintext = CryptoService.decrypt(aes(unwrapDek(meta, PASSWORD)), meta.verifier());
        assertArrayEquals(CANARY_PLAINTEXT.getBytes(StandardCharsets.UTF_8), plaintext);
    }

    /**
     * The reason a wrong password is reported as a wrong password instead of surfacing later as
     * garbage: unwrapping fails the GCM tag check.
     */
    @Test
    void refusesToUnwrapTheDekWithTheWrongPassword(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        Meta meta = readMeta(paths);
        assertThrows(AEADBadTagException.class, () -> unwrapDek(meta, WRONG_PASSWORD));
    }

    /**
     * The canary is encrypted under the DEK on purpose. Under the master key it would only repeat
     * the tag check unwrapping already performs, and would not prove the DEK came back intact.
     */
    @Test
    void encryptsTheCanaryUnderTheDekAndNotTheMasterKey(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        Meta meta = readMeta(paths);
        SecretKey masterKey = deriveMasterKey(meta, PASSWORD);
        assertThrows(AEADBadTagException.class, () -> CryptoService.decrypt(masterKey, meta.verifier()));
    }

    /**
     * If the DEK were derived from the password rather than drawn at random, changing the master
     * password could not leave the entries alone — and the indirection would buy nothing.
     */
    @Test
    void drawsADekIndependentOfTheMasterKey(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        Meta meta = readMeta(paths);
        assertFalse(java.util.Arrays.equals(deriveMasterKey(meta, PASSWORD).getEncoded(),
                unwrapDek(meta, PASSWORD)), "the DEK must not be the master key");
    }

    /**
     * Two vaults sharing a salt would let one cracked password carry over, and two sharing an IV
     * under the same key would break GCM outright. Nothing random here may repeat, even when the
     * password is identical.
     */
    @Test
    void reusesNothingBetweenTwoVaultsMadeFromTheSamePassword(@TempDir Path tempDir) throws Exception {
        VaultPaths first = pathsIn(tempDir, "first");
        VaultPaths second = pathsIn(tempDir, "second");

        initializer(first).initialize(PASSWORD);
        initializer(second).initialize(PASSWORD);

        Meta a = readMeta(first);
        Meta b = readMeta(second);
        assertDiffers(a, b, KEY_KDF_SALT);
        assertDiffers(a, b, KEY_WRAPPED_DEK_IV);
        assertDiffers(a, b, KEY_WRAPPED_DEK);
        assertDiffers(a, b, KEY_VERIFIER_IV);
        assertDiffers(a, b, KEY_VERIFIER_CT);
        assertFalse(java.util.Arrays.equals(unwrapDek(a, PASSWORD), unwrapDek(b, PASSWORD)),
                "two vaults must not share a DEK");
    }

    /** Two IVs drawn for the same vault must differ too — a fixed IV would be the same bug. */
    @Test
    void drawsAFreshIvForEveryCiphertext(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        Meta meta = readMeta(paths);
        assertFalse(java.util.Arrays.equals(meta.bytes(KEY_WRAPPED_DEK_IV), meta.bytes(KEY_VERIFIER_IV)),
                "the wrapped DEK and the canary must not share an IV");
    }

    /**
     * Reads the raw file rather than the tables: the danger is a plaintext copy anywhere in the
     * database — a stale page, a freelist entry — not only in the column that was meant to hold it.
     */
    @Test
    void writesNoPlaintextSecretIntoTheDatabaseFile(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        byte[] file = Files.readAllBytes(paths.databaseFile());
        assertFalse(contains(file, CANARY_PLAINTEXT.getBytes(StandardCharsets.UTF_8)),
                "the canary plaintext is on disk");
        assertFalse(contains(file, new String(PASSWORD).getBytes(StandardCharsets.UTF_8)),
                "the master password is on disk");
    }

    /** The derived key never leaves memory; only the salt and the parameters are stored. */
    @Test
    void writesNoKeyMaterialIntoTheDatabaseFile(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        Meta meta = readMeta(paths);
        byte[] file = Files.readAllBytes(paths.databaseFile());
        assertFalse(contains(file, deriveMasterKey(meta, PASSWORD).getEncoded()), "the master key is on disk");
        assertFalse(contains(file, unwrapDek(meta, PASSWORD)), "the DEK is on disk in the clear");
    }

    // ---------------------------------------------------------------- the caller's password

    /**
     * The class documents that it reads the password and never clears it, because the caller may
     * still need it — to confirm it, or to open the vault it has just created. Clearing it here
     * would hand the caller an array of zeros without saying so.
     */
    @Test
    void doesNotClearThePasswordItWasGiven(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);
        char[] password = "still needed afterwards".toCharArray();

        initializer(paths).initialize(password);

        assertArrayEquals("still needed afterwards".toCharArray(), password);
    }

    /**
     * Passwords are encoded as UTF-8 rather than going through {@link String}, so anything outside
     * ASCII is where an encoding bug would show up — as a vault nobody can open.
     */
    @Test
    void handlesANonAsciiPassword(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);
        char[] password = "zażółć gęślą jaźń 🔐".toCharArray();

        initializer(paths).initialize(password);

        assertEquals(DEK_LENGTH_BYTES, unwrapDek(readMeta(paths), password).length);
    }

    /**
     * Documents where the policy lives: refusing a weak or empty password is {@code InitCommand}'s
     * job, so this class treats an empty array as a password like any other rather than silently
     * creating something different.
     */
    @Test
    void treatsAnEmptyPasswordLikeAnyOther(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(new char[0]);

        assertEquals(DEK_LENGTH_BYTES, unwrapDek(readMeta(paths), new char[0]).length);
        assertThrows(AEADBadTagException.class, () -> unwrapDek(readMeta(paths), PASSWORD));
    }

    // ---------------------------------------------------------------- refusing to overwrite

    /** Overwriting a vault destroys every secret in it, irreversibly. */
    @Test
    void refusesWhenAVaultAlreadyExists(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);
        initializer(paths).initialize(PASSWORD);

        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> initializer(paths).initialize(PASSWORD));

        assertTrue(thrown.getMessage().contains(paths.databaseFile().toString()),
                "the message should name the vault that is in the way: " + thrown.getMessage());
    }

    @Test
    void leavesTheExistingVaultUntouchedWhenItRefuses(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);
        initializer(paths).initialize(PASSWORD);
        byte[] before = Files.readAllBytes(paths.databaseFile());

        assertThrows(IllegalStateException.class, () -> initializer(paths).initialize(WRONG_PASSWORD));

        assertArrayEquals(before, Files.readAllBytes(paths.databaseFile()));
        assertEquals(List.of(DATABASE_NAME), fileNamesIn(paths.vaultHome()));
        assertEquals(DEK_LENGTH_BYTES, unwrapDek(readMeta(paths), PASSWORD).length);
    }

    /** Refusing must not be the thing that creates the vault directory. */
    @Test
    void doesNotTouchTheFilesystemWhenItRefuses(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);
        initializer(paths).initialize(PASSWORD);
        Files.delete(paths.databaseFile());
        Files.delete(paths.vaultHome());
        // a directory in the vault's place: not a vault, so this run must go ahead and fail on the
        // move instead of being turned away
        Files.createDirectories(paths.databaseFile());

        assertThrows(IOException.class, () -> initializer(paths).initialize(PASSWORD));

        assertTrue(Files.isDirectory(paths.databaseFile()));
        assertEquals(List.of(DATABASE_NAME), fileNamesIn(paths.vaultHome()));
    }

    // ---------------------------------------------------------------- interrupted runs

    /**
     * A run killed before it claimed its vault leaves a {@code .db.tmp} behind. Names are unique
     * per run, so nothing else would ever collect it — and it holds a wrapped DEK the user's
     * password unwraps, which is not something to leave lying around.
     */
    @Test
    void sweepsTheDatabaseLeftByAnInterruptedRun(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);
        paths.ensureVaultDirectory();
        Path stale = paths.vaultHome().resolve(LEFTOVER_NAME);
        try (VaultDatabase leftover = VaultDatabase.open(stale)) {
            leftover.inTransaction(connection -> {
                storage.SchemaInitializer.createSchema(connection);
                return null;
            });
        }

        initializer(paths).initialize(PASSWORD);

        assertEquals(List.of(DATABASE_NAME), fileNamesIn(paths.vaultHome()));
        assertEquals(DEK_LENGTH_BYTES, unwrapDek(readMeta(paths), PASSWORD).length);
    }

    @Test
    void sweepsUnrelatedRubbishLeftUnderATemporaryName(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);
        paths.ensureVaultDirectory();
        for (String suffix : List.of("", "-wal", "-shm")) {
            Files.writeString(paths.vaultHome().resolve(LEFTOVER_NAME + suffix), "not a database");
        }

        initializer(paths).initialize(PASSWORD);

        assertEquals(List.of(DATABASE_NAME), fileNamesIn(paths.vaultHome()));
        assertEquals(DEK_LENGTH_BYTES, unwrapDek(readMeta(paths), PASSWORD).length);
    }

    /**
     * The dangerous leftover is the side file. A run killed mid-write leaves a {@code -wal} holding
     * pages that were never checkpointed; left in place next to a fresh database, SQLite replays
     * them into it, so the new vault silently inherits the dead run's contents. Removing only the
     * main file is not enough.
     */
    @Test
    void removesTheWalLeftByAnInterruptedRun(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);
        paths.ensureVaultDirectory();
        restoreInterruptedRun(tempDir.resolve("interrupted"), paths.vaultHome());

        initializer(paths).initialize(PASSWORD);

        assertEquals(List.of(DATABASE_NAME), fileNamesIn(paths.vaultHome()));
        assertEquals(List.of("entries", "vault_meta"), tableNames(paths.databaseFile()));
        assertEquals(DEK_LENGTH_BYTES, unwrapDek(readMeta(paths), PASSWORD).length);
    }

    /**
     * A failed run must not leave a half-built vault where the next run would find it, and must not
     * leave the temporary copy of the secrets behind either.
     */
    @Test
    void cleansUpTheTemporaryFilesWhenTheRunFails(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);
        paths.ensureVaultDirectory();
        // a non-empty directory at the target path: everything succeeds until the move
        Files.createDirectories(paths.databaseFile().resolve("in the way"));

        assertThrows(IOException.class, () -> initializer(paths).initialize(PASSWORD));

        assertEquals(List.of(DATABASE_NAME), fileNamesIn(paths.vaultHome()));
        assertFalse(paths.vaultExists());
    }

    /** After a failed run the path is clear again, so a retry must simply work. */
    @Test
    void canRetryAfterAFailedRun(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);
        paths.ensureVaultDirectory();
        Files.createDirectories(paths.databaseFile().resolve("in the way"));
        assertThrows(IOException.class, () -> initializer(paths).initialize(PASSWORD));
        Files.delete(paths.databaseFile().resolve("in the way"));
        Files.delete(paths.databaseFile());

        initializer(paths).initialize(PASSWORD);

        assertEquals(DEK_LENGTH_BYTES, unwrapDek(readMeta(paths), PASSWORD).length);
    }

    /** An unwritable vault directory must fail outright rather than leave something unopenable. */
    @Test
    void failsWithoutCreatingAnythingWhenTheDirectoryCannotBeWritten(@TempDir Path tempDir) throws Exception {
        assumeFalse("root".equals(System.getProperty("user.name")), "root ignores file permissions");
        VaultPaths paths = pathsIn(tempDir);
        paths.ensureVaultDirectory();
        Files.setPosixFilePermissions(paths.vaultHome(), PosixFilePermissions.fromString("r-x------"));

        try {
            assertThrows(Exception.class, () -> initializer(paths).initialize(PASSWORD));
            assertEquals(List.of(), fileNamesIn(paths.vaultHome()));
        } finally {
            Files.setPosixFilePermissions(paths.vaultHome(), PosixFilePermissions.fromString("rwx------"));
        }
    }

    // ---------------------------------------------------------------- two runs at once

    /**
     * The guard that replaced {@code Files.move}: a move overwrites whatever it finds, so of two
     * runs racing each other both would report success while one vault quietly disappeared.
     */
    @Test
    void claimingPutsTheVaultAtTheTargetPath(@TempDir Path tempDir) throws Exception {
        Path built = Files.writeString(tempDir.resolve("built"), "a finished vault");
        Path target = tempDir.resolve(DATABASE_NAME);

        VaultInitializer.claim(target, built);

        assertEquals("a finished vault", Files.readString(target));
        assertTrue(Files.isSameFile(built, target), "the claim should not copy the file");
    }

    @Test
    void claimingRefusesWhenAVaultIsAlreadyThere(@TempDir Path tempDir) throws Exception {
        Path built = Files.writeString(tempDir.resolve("built"), "the vault this run just built");
        Path target = Files.writeString(tempDir.resolve(DATABASE_NAME), "the vault that got there first");

        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> VaultInitializer.claim(target, built));

        assertTrue(thrown.getMessage().contains(target.toString()), thrown.getMessage());
        assertEquals("the vault that got there first", Files.readString(target),
                "the vault that was already there must survive untouched");
    }

    /** Not every occupied path holds a vault, and saying it does would send the user looking for one. */
    @Test
    void claimingReportsSomethingOtherThanAVaultInTheWayAsAnIoFailure(@TempDir Path tempDir) throws Exception {
        Path built = Files.writeString(tempDir.resolve("built"), "a finished vault");
        Path target = tempDir.resolve(DATABASE_NAME);
        Files.createDirectory(target);

        assertThrows(IOException.class, () -> VaultInitializer.claim(target, built));
    }

    /**
     * The whole point of the fix, end to end: several runs starting at the same moment all pass the
     * check at the top of {@code initialize}, and exactly one of them may come away with a vault.
     * The rest must fail — never overwrite what the winner wrote, and never leave the winner with
     * a vault its own password cannot open.
     */
    @Test
    void letsOnlyOneOfSeveralSimultaneousRunsCreateTheVault(@TempDir Path tempDir) throws Exception {
        int runs = 4;
        VaultPaths paths = pathsIn(tempDir);
        paths.ensureVaultDirectory();
        CyclicBarrier readyToGo = new CyclicBarrier(runs);

        List<char[]> passwords = new ArrayList<>();
        List<Callable<String>> attempts = new ArrayList<>();
        for (int run = 0; run < runs; run++) {
            char[] password = ("password of run " + run).toCharArray();
            passwords.add(password);
            attempts.add(() -> {
                readyToGo.await(10, TimeUnit.SECONDS);
                initializer(paths).initialize(password);
                return new String(password);
            });
        }

        List<String> winners = new ArrayList<>();
        List<Throwable> refusals = new ArrayList<>();
        ExecutorService pool = Executors.newFixedThreadPool(runs);
        try {
            for (Future<String> attempt : pool.invokeAll(attempts)) {
                try {
                    winners.add(attempt.get());
                } catch (ExecutionException e) {
                    refusals.add(e.getCause());
                }
            }
        } finally {
            pool.shutdownNow();
        }

        assertEquals(1, winners.size(), "exactly one run may create the vault, got " + winners + " " + refusals);
        assertEquals(runs - 1, refusals.size());
        refusals.forEach(refusal -> assertInstanceOf(Exception.class, refusal));

        // the survivor is a whole vault, and it is the winner's
        char[] winner = winners.get(0).toCharArray();
        assertEquals(List.of(DATABASE_NAME), fileNamesIn(paths.vaultHome()));
        assertEquals(List.of("entries", "vault_meta"), tableNames(paths.databaseFile()));
        assertEquals(8, countRows(paths.databaseFile(), "vault_meta"));
        assertEquals(DEK_LENGTH_BYTES, unwrapDek(readMeta(paths), winner).length);
        for (char[] password : passwords) {
            if (!java.util.Arrays.equals(password, winner)) {
                assertThrows(AEADBadTagException.class, () -> unwrapDek(readMeta(paths), password));
            }
        }
    }

    // ---------------------------------------------------------------- durability of the result

    /**
     * The vault is moved into place while its WAL has already been checkpointed back, so what
     * lands at the target path is complete on its own. Reading it through a fresh connection is
     * what proves the move did not carry away half a database.
     */
    @Test
    void movesACompleteDatabaseIntoPlace(@TempDir Path tempDir) throws Exception {
        VaultPaths paths = pathsIn(tempDir);

        initializer(paths).initialize(PASSWORD);

        assertEquals(List.of(DATABASE_NAME), fileNamesIn(paths.vaultHome()));
        assertEquals(8, countRows(paths.databaseFile(), "vault_meta"));
        assertEquals(List.of("entries", "vault_meta"), tableNames(paths.databaseFile()));
    }

    /** Vaults in different directories are independent; creating one must not disturb the other. */
    @Test
    void createsIndependentVaultsInDifferentDirectories(@TempDir Path tempDir) throws Exception {
        VaultPaths first = pathsIn(tempDir, "first");
        VaultPaths second = pathsIn(tempDir, "second");
        char[] otherPassword = "a different one".toCharArray();

        initializer(first).initialize(PASSWORD);
        initializer(second).initialize(otherPassword);

        assertEquals(DEK_LENGTH_BYTES, unwrapDek(readMeta(first), PASSWORD).length);
        assertEquals(DEK_LENGTH_BYTES, unwrapDek(readMeta(second), otherPassword).length);
        assertThrows(AEADBadTagException.class, () -> unwrapDek(readMeta(first), otherPassword));
        assertThrows(AEADBadTagException.class, () -> unwrapDek(readMeta(second), PASSWORD));
    }

    // ---------------------------------------------------------------- helpers

    private static VaultInitializer initializer(VaultPaths paths) {
        return new VaultInitializer(paths, TEST_PARAMS);
    }

    private static VaultPaths pathsIn(Path tempDir) {
        return pathsIn(tempDir, "vault-home");
    }

    private static VaultPaths pathsIn(Path tempDir, String name) {
        return new VaultPaths(tempDir.resolve(name));
    }

    private static void assertDiffers(Meta first, Meta second, String key) {
        assertFalse(java.util.Arrays.equals(first.bytes(key), second.bytes(key)),
                key + " must not be reused between vaults");
    }

    private static SecretKey deriveMasterKey(Meta meta, char[] password) {
        return KeyDerivation.deriveKey(password, meta.bytes(KEY_KDF_SALT),
                KdfParams.parse(meta.text(KEY_KDF_PARAMS)));
    }

    /** Walks the same chain opening a vault would: password to master key to DEK. */
    private static byte[] unwrapDek(Meta meta, char[] password) throws GeneralSecurityException {
        return CryptoService.decrypt(deriveMasterKey(meta, password),
                new EncryptedData(meta.bytes(KEY_WRAPPED_DEK_IV), meta.bytes(KEY_WRAPPED_DEK)));
    }

    private static SecretKey aes(byte[] material) {
        return new SecretKeySpec(material, "AES");
    }

    private static Meta readMeta(VaultPaths paths) throws Exception {
        Map<String, Object> values = new LinkedHashMap<>();
        Map<String, String> types = new LinkedHashMap<>();

        try (VaultDatabase vault = VaultDatabase.open(paths.databaseFile());
             Statement statement = vault.connection().createStatement();
             ResultSet resultSet = statement.executeQuery(
                     "SELECT key, value, typeof(value) FROM vault_meta ORDER BY key")) {
            while (resultSet.next()) {
                String key = resultSet.getString(1);
                String type = resultSet.getString(3);
                values.put(key, switch (type) {
                    case "integer" -> resultSet.getLong(2);
                    case "text" -> resultSet.getString(2);
                    default -> resultSet.getBytes(2);
                });
                types.put(key, type);
            }
        }
        return new Meta(values, types);
    }

    private static int countRows(Path databaseFile, String table) throws Exception {
        try (VaultDatabase vault = VaultDatabase.open(databaseFile);
             Statement statement = vault.connection().createStatement();
             ResultSet resultSet = statement.executeQuery("SELECT count(*) FROM " + table)) {
            return resultSet.next() ? resultSet.getInt(1) : -1;
        }
    }

    private static List<String> tableNames(Path databaseFile) throws Exception {
        try (VaultDatabase vault = VaultDatabase.open(databaseFile);
             Statement statement = vault.connection().createStatement();
             ResultSet resultSet = statement.executeQuery(
                     "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")) {
            List<String> names = new ArrayList<>();
            while (resultSet.next()) {
                names.add(resultSet.getString(1));
            }
            return names;
        }
    }

    /**
     * Copies what a run killed before its database was closed leaves behind — the database and its
     * uncheckpointed {@code -wal} and {@code -shm} — into {@code vaultHome}. The files are taken
     * while the connection is still open, which is the only way to capture a WAL that was never
     * checkpointed back.
     */
    private static void restoreInterruptedRun(Path staging, Path vaultHome) throws Exception {
        Files.createDirectories(staging);
        Path database = staging.resolve(LEFTOVER_NAME);

        try (VaultDatabase interrupted = VaultDatabase.open(database)) {
            interrupted.inTransaction(connection -> {
                try (Statement statement = connection.createStatement()) {
                    statement.execute("CREATE TABLE leftover_from_a_dead_run(id INTEGER PRIMARY KEY)");
                }
                return null;
            });

            for (String suffix : List.of("", "-wal", "-shm")) {
                Path side = staging.resolve(LEFTOVER_NAME + suffix);
                if (Files.exists(side)) {
                    Files.copy(side, vaultHome.resolve(LEFTOVER_NAME + suffix));
                }
            }
        }
    }

    private static List<String> fileNamesIn(Path directory) throws IOException {
        try (Stream<Path> entries = Files.list(directory)) {
            return entries.map(path -> path.getFileName().toString()).sorted().toList();
        }
    }

    private static String permissionsOf(Path path) throws IOException {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(path));
    }

    /** Naive search; the files involved are a few kilobytes. */
    private static boolean contains(byte[] haystack, byte[] needle) {
        if (needle.length == 0) {
            return true;
        }
        outer:
        for (int start = 0; start + needle.length <= haystack.length; start++) {
            for (int offset = 0; offset < needle.length; offset++) {
                if (haystack[start + offset] != needle[offset]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    /** The {@code vault_meta} rows, read back with the type each one was stored as. */
    private record Meta(Map<String, Object> values, Map<String, String> types) {

        byte[] bytes(String key) {
            return (byte[]) values.get(key);
        }

        long number(String key) {
            return (long) values.get(key);
        }

        String text(String key) {
            return (String) values.get(key);
        }

        EncryptedData verifier() {
            return new EncryptedData(bytes(KEY_VERIFIER_IV), bytes(KEY_VERIFIER_CT));
        }
    }
}
