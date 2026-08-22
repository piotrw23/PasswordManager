package storage;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

/**
 * One open connection to a vault database file, with the settings a vault depends on already
 * applied.
 *
 * <p>Every connection to the vault is opened here so that the two PRAGMAs below are never missed.
 * They behave differently, which is the reason this class exists rather than a bare
 * {@link java.sql.DriverManager#} call at each use site:
 *
 * <ul>
 *   <li>{@code foreign_keys} is per-connection and defaults to <em>off</em> in SQLite, so it has to
 *       be set again on every open. Forgetting it does not fail — the constraints are simply not
 *       enforced, silently.
 *   <li>{@code journal_mode = WAL} is stored in the database file header, so it survives reopening
 *       and only needs to take effect once.
 * </ul>
 *
 * <p>The file to open is a parameter rather than something read from {@code VaultPaths}: a new
 * vault is built under a temporary path and moved into place only once it is complete, so this
 * class must be able to open any path it is handed.
 *
 * <p><strong>WAL and moving the file:</strong> in WAL mode SQLite keeps recently committed data in
 * a side file next to the database ({@code -wal}, plus {@code -shm}). Closing the last connection
 * cleanly checkpoints that data back into the main file and removes the side files. Anything that
 * relocates a vault must therefore {@link #close()} first and move afterwards, or it will move a
 * database that is missing its most recent commits.
 */
public final class VaultDatabase implements AutoCloseable {

    private static final String JDBC_URL_PREFIX = "jdbc:sqlite:";

    /** What {@code PRAGMA journal_mode} reports once WAL is in effect. */
    private static final String WAL_MODE = "wal";

    /**
     * Permissions for the database file itself. {@code VaultPaths} already makes the enclosing
     * directory owner-only, which is what actually keeps other users out; this is a second layer
     * for the case where the file is copied or the directory is later loosened. SQLite creates the
     * file using the process umask, which is typically world-readable.
     */
    private static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rw-------");

    private final Connection connection;
    private final Path databaseFile;

    private VaultDatabase(Connection connection, Path databaseFile) {
        this.connection = connection;
        this.databaseFile = databaseFile;
    }

    /**
     * Opens {@code databaseFile}, creating it when it does not exist, and applies the vault's
     * connection settings.
     *
     * @param databaseFile the vault database; its parent directory must already exist
     * @return an open, configured database handle owned by the caller
     * @throws IOException  if the file cannot be created with owner-only permissions
     * @throws SQLException if the connection cannot be opened or configured
     */
    public static VaultDatabase open(Path databaseFile) throws IOException, SQLException {
        Path file = databaseFile.toAbsolutePath().normalize();
        createOwnerOnlyFile(file);

        Connection connection = DriverManager.getConnection(JDBC_URL_PREFIX + file);
        try {
            applyConnectionSettings(connection);
            return new VaultDatabase(connection, file);
        } catch (SQLException | RuntimeException e) {
            // a caller that never receives the handle cannot close it, so a connection that was
            // opened but not fully configured has to be released here
            try {
                connection.close();
            } catch (SQLException closeFailure) {
                e.addSuppressed(closeFailure);
            }
            throw e;
        }
    }

    /**
     * Creates the database file with {@link #OWNER_ONLY} permissions, or leaves it alone when it
     * already exists.
     *
     * <p>SQLite would create the file itself on connect, but with whatever the process umask
     * allows — commonly world-readable. Creating an empty file up front, with the permissions
     * passed as an attribute, means the vault is never readable by anyone else, not even for the
     * moment between creating the file and chmod-ing it. An empty file is a valid empty database,
     * so SQLite is happy to take it from there.
     *
     * <p>This covers the database file only. The {@code -wal} and {@code -shm} side files are
     * created by SQLite later and do follow the umask; what keeps those private is the owner-only
     * vault directory.
     */
    private static void createOwnerOnlyFile(Path file) throws IOException {
        try {
            Files.createFile(file, PosixFilePermissions.asFileAttribute(OWNER_ONLY));
        } catch (FileAlreadyExistsException expected) {
            // opening an existing vault is the normal case
        }
    }

    private static void applyConnectionSettings(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            // silently ignored inside a transaction, which a freshly opened connection never is
            statement.execute("PRAGMA foreign_keys = ON");

            // this PRAGMA answers with the mode that actually took effect. WAL needs shared memory
            // and is refused on filesystems that cannot provide it, such as some network mounts,
            // where SQLite quietly stays on the rollback journal instead of reporting an error
            try (ResultSet resultSet = statement.executeQuery("PRAGMA journal_mode = WAL")) {
                String mode = resultSet.next() ? resultSet.getString(1) : null;
                if (!WAL_MODE.equalsIgnoreCase(mode)) {
                    throw new SQLException("Could not switch " + connection.getMetaData().getURL()
                            + " to WAL mode, journal_mode is " + mode);
                }
            }
        }
    }

    /**
     * Runs {@code work} inside a single transaction, committing when it returns and rolling back
     * when it throws.
     *
     * <p>Creating a vault writes the schema and every metadata row as one unit — a database
     * carrying tables but no KDF salt could never be opened, and must not be left behind. SQLite
     * makes this possible for DDL too: unlike most engines it can roll back {@code CREATE TABLE}.
     *
     * <p>Nesting is rejected rather than silently mishandled: an inner {@code commit} would commit
     * the outer work as well. SQLite can nest through {@code SAVEPOINT}s, which the vault does not
     * need and this method does not use.
     *
     * @throws IllegalStateException if a transaction is already open on this connection
     */
    public <T> T inTransaction(SqlWork<T> work) throws SQLException {
        if (!connection.getAutoCommit()) {
            throw new IllegalStateException("A transaction is already open on " + databaseFile);
        }

        connection.setAutoCommit(false);
        T result;
        try {
            result = work.apply(connection);
            connection.commit();
        } catch (SQLException | RuntimeException e) {
            abortQuietly(e);
            throw e;
        }

        // deliberately outside the catch: the work is already committed, so failing to hand the
        // connection back in auto-commit mode is a fault of its own and not something to suppress
        connection.setAutoCommit(true);
        return result;
    }

    /**
     * Discards the failed transaction and returns the connection to auto-commit, reporting any
     * problem as a suppressed exception on {@code primary}.
     *
     * <p>Neither step may throw on its own: a {@code finally} block that throws replaces the
     * exception being propagated, which would hide why the transaction failed in the first place.
     * Restoring auto-commit has to come after the rollback, since switching it back on while a
     * transaction is still open commits that transaction.
     */
    private void abortQuietly(Throwable primary) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            primary.addSuppressed(rollbackFailure);
        }

        try {
            connection.setAutoCommit(true);
        } catch (SQLException restoreFailure) {
            primary.addSuppressed(restoreFailure);
        }
    }

    /**
     * The underlying connection, for statements that run outside a transaction.
     *
     * <p>Stays open until this object is closed; callers must not close it themselves.
     */
    public Connection connection() {
        return connection;
    }

    /** The file this connection is attached to. */
    public Path databaseFile() {
        return databaseFile;
    }

    @Override
    public void close() throws SQLException {
        connection.close();
    }

    /**
     * A unit of work against an open connection. Separate from {@link java.util.function.Function}
     * because everything JDBC does throws the checked {@link SQLException}.
     */
    @FunctionalInterface
    public interface SqlWork<T> {
        T apply(Connection connection) throws SQLException;
    }
}
