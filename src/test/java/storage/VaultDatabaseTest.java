package storage;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VaultDatabaseTest {

    @Test
    void createsTheDatabaseFileWhenItIsMissing(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("vault.db");
        assertFalse(Files.exists(file));

        try (VaultDatabase vault = VaultDatabase.open(file)) {
            assertTrue(Files.isRegularFile(file));
            assertFalse(vault.connection().isClosed());
        }
    }

    /**
     * SQLite would create the file with whatever the umask allows, which is normally readable by
     * everyone. The vault directory is the real barrier, but the file must not rely on it.
     */
    @Test
    void createsTheDatabaseFileReadableOnlyByItsOwner(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("vault.db");

        try (VaultDatabase ignored = VaultDatabase.open(file)) {
            assertEquals("rw-------", permissionsOf(file));
        }
    }

    @Test
    void keepsAnExistingDatabaseAndItsContents(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("vault.db");
        try (VaultDatabase vault = VaultDatabase.open(file)) {
            execute(vault.connection(), "CREATE TABLE vault_meta(key TEXT PRIMARY KEY, value BLOB)");
        }

        try (VaultDatabase reopened = VaultDatabase.open(file)) {
            assertEquals(List.of("vault_meta"), tableNames(reopened.connection()));
            assertEquals("rw-------", permissionsOf(file));
        }
    }

    /** Foreign keys default to off in SQLite and have to be switched on for every connection. */
    @Test
    void enforcesForeignKeys(@TempDir Path tempDir) throws Exception {
        try (VaultDatabase vault = VaultDatabase.open(tempDir.resolve("vault.db"))) {
            Connection connection = vault.connection();
            execute(connection, "CREATE TABLE parent(id INTEGER PRIMARY KEY)");
            execute(connection, "CREATE TABLE child(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id))");

            assertThrows(SQLException.class,
                    () -> execute(connection, "INSERT INTO child(id, parent_id) VALUES (1, 99)"));
        }
    }

    @Test
    void switchesTheDatabaseToWalMode(@TempDir Path tempDir) throws Exception {
        try (VaultDatabase vault = VaultDatabase.open(tempDir.resolve("vault.db"))) {
            assertEquals("wal", queryString(vault.connection(), "PRAGMA journal_mode"));
        }
    }

    @Test
    void reportsAnAbsoluteNormalisedPath(@TempDir Path tempDir) throws Exception {
        Path indirect = tempDir.resolve("elsewhere").resolve("..").resolve("vault.db");

        try (VaultDatabase vault = VaultDatabase.open(indirect)) {
            assertEquals(tempDir.toAbsolutePath().resolve("vault.db"), vault.databaseFile());
        }
    }

    @Test
    void failsWhenTheVaultDirectoryIsMissing(@TempDir Path tempDir) {
        Path insideMissingDirectory = tempDir.resolve("no-such-directory").resolve("vault.db");

        assertThrows(IOException.class, () -> VaultDatabase.open(insideMissingDirectory));
    }

    /**
     * In WAL mode committed data can still be sitting in the {@code -wal} side file. Closing the
     * last connection checkpoints it back, which is what makes the database file safe to move.
     */
    @Test
    void checkpointsAndRemovesTheWalFilesOnClose(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("vault.db");

        try (VaultDatabase vault = VaultDatabase.open(file)) {
            execute(vault.connection(), "CREATE TABLE vault_meta(key TEXT PRIMARY KEY, value BLOB)");
            assertEquals(List.of("vault.db", "vault.db-shm", "vault.db-wal"), fileNamesIn(tempDir));
        }

        assertEquals(List.of("vault.db"), fileNamesIn(tempDir));
        try (VaultDatabase reopened = VaultDatabase.open(file)) {
            assertEquals(List.of("vault_meta"), tableNames(reopened.connection()));
        }
    }

    @Test
    void closesTheUnderlyingConnection(@TempDir Path tempDir) throws Exception {
        VaultDatabase vault = VaultDatabase.open(tempDir.resolve("vault.db"));
        Connection connection = vault.connection();

        vault.close();

        assertTrue(connection.isClosed());
    }

    @Test
    void commitsTheWorkAndReturnsItsResult(@TempDir Path tempDir) throws Exception {
        try (VaultDatabase vault = VaultDatabase.open(tempDir.resolve("vault.db"))) {
            execute(vault.connection(), "CREATE TABLE vault_meta(key TEXT PRIMARY KEY, value BLOB)");

            String stored = vault.inTransaction(connection -> {
                execute(connection, "INSERT INTO vault_meta(key, value) VALUES ('schema_version', x'01')");
                return "done";
            });

            assertEquals("done", stored);
            assertEquals(1, rowCount(vault.connection()));
            assertTrue(vault.connection().getAutoCommit());
        }
    }

    /**
     * SQLite can roll back {@code CREATE TABLE}, so creating the schema and filling it can be one
     * unit of work. A vault with tables but no metadata could never be opened again.
     */
    @Test
    void rollsBackSchemaAndDataWhenTheWorkFails(@TempDir Path tempDir) throws Exception {
        try (VaultDatabase vault = VaultDatabase.open(tempDir.resolve("vault.db"))) {

            SQLException thrown = assertThrows(SQLException.class, () -> vault.inTransaction(connection -> {
                execute(connection, "CREATE TABLE vault_meta(key TEXT PRIMARY KEY, value BLOB)");
                execute(connection, "INSERT INTO vault_meta(key, value) VALUES ('schema_version', x'01')");
                throw new SQLException("writing the metadata failed");
            }));

            assertEquals("writing the metadata failed", thrown.getMessage());
            assertEquals(List.of(), tableNames(vault.connection()));
            assertTrue(vault.connection().getAutoCommit());
        }
    }

    @Test
    void rollsBackWhenTheWorkThrowsARuntimeException(@TempDir Path tempDir) throws Exception {
        try (VaultDatabase vault = VaultDatabase.open(tempDir.resolve("vault.db"))) {
            execute(vault.connection(), "CREATE TABLE vault_meta(key TEXT PRIMARY KEY, value BLOB)");

            assertThrows(IllegalStateException.class, () -> vault.inTransaction(connection -> {
                execute(connection, "INSERT INTO vault_meta(key, value) VALUES ('schema_version', x'01')");
                throw new IllegalStateException("the caller gave up");
            }));

            assertEquals(0, rowCount(vault.connection()));
            assertTrue(vault.connection().getAutoCommit());
        }
    }

    @Test
    void handsTheWorkTheConnectionItRunsOn(@TempDir Path tempDir) throws Exception {
        try (VaultDatabase vault = VaultDatabase.open(tempDir.resolve("vault.db"))) {
            Connection passedIn = vault.inTransaction(connection -> connection);

            assertSame(vault.connection(), passedIn);
        }
    }

    /** An inner commit would silently commit the outer work as well. */
    @Test
    void rejectsNestedTransactions(@TempDir Path tempDir) throws Exception {
        try (VaultDatabase vault = VaultDatabase.open(tempDir.resolve("vault.db"))) {

            assertThrows(IllegalStateException.class,
                    () -> vault.inTransaction(outer -> vault.inTransaction(inner -> null)));

            assertTrue(vault.connection().getAutoCommit());
        }
    }

    @Test
    void canRunSeveralTransactionsInSequence(@TempDir Path tempDir) throws Exception {
        try (VaultDatabase vault = VaultDatabase.open(tempDir.resolve("vault.db"))) {
            vault.inTransaction(connection -> {
                execute(connection, "CREATE TABLE vault_meta(key TEXT PRIMARY KEY, value BLOB)");
                return null;
            });
            vault.inTransaction(connection -> {
                execute(connection, "INSERT INTO vault_meta(key, value) VALUES ('schema_version', x'01')");
                return null;
            });

            assertEquals(1, rowCount(vault.connection()));
        }
    }

    private static void execute(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private static String queryString(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            return resultSet.next() ? resultSet.getString(1) : null;
        }
    }

    private static int rowCount(Connection connection) throws SQLException {
        return Integer.parseInt(queryString(connection, "SELECT count(*) FROM vault_meta"));
    }

    private static List<String> tableNames(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(
                     "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")) {
            List<String> names = new java.util.ArrayList<>();
            while (resultSet.next()) {
                names.add(resultSet.getString(1));
            }
            return names;
        }
    }

    private static List<String> fileNamesIn(Path directory) throws IOException {
        try (Stream<Path> entries = Files.list(directory)) {
            return entries.map(path -> path.getFileName().toString()).sorted().toList();
        }
    }

    private static String permissionsOf(Path file) throws IOException {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(file));
    }
}
