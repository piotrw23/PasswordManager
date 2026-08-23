package storage;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * The definition of what a vault database contains.
 *
 * <p>Every table and column the vault has is declared here, once, as the DDL below. Nothing else
 * creates tables, so the schema can be read in one place instead of being reconstructed from the
 * statements scattered across whatever code happens to write to it.
 *
 * <p>It takes a {@link Connection} rather than a {@link VaultDatabase} on purpose: creating the
 * schema is never the whole job. Initialising a vault writes the tables <em>and</em> the metadata
 * that make it openable, and a database holding one without the other is useless — so the caller
 * owns the transaction and this class simply runs inside it. See
 * {@link VaultDatabase#inTransaction}.
 *
 * <p>The tables are {@code STRICT}. Without it SQLite applies type affinity rather than type
 * checking, and a column declared {@code BLOB} would silently accept text or a number; with it the
 * declared types are enforced, so a bug that stores a ciphertext as text fails at the insert
 * instead of at some later read.
 */
public final class SchemaInitializer {

    /**
     * Everything needed to open the vault, as opaque bytes under a well-known key: the KDF salt
     * and parameters, the wrapped DEK with its IV, the canary, the schema version and the creation
     * time.
     *
     * <p>Key/value rather than one column per field because these are read individually and rarely,
     * and because the set grows over time — adding a key needs no migration.
     *
     * <p>{@code value} is declared {@code ANY} because the rows genuinely differ in kind: the
     * schema version and the creation time are numbers, the encoded KDF parameters are text, and
     * the salt, wrapped DEK and canary are bytes. Each keeps the type it naturally has, so the
     * table stays readable with {@code sqlite3} instead of showing hex for everything.
     *
     * <p>{@code ANY} is not a hole in the {@code STRICT} guarantee: in a strict table it stores
     * every value exactly as given, without the numeric affinity a lax table would apply to text
     * that looks like a number. What it gives up is the schema saying which key holds which type —
     * that knowledge lives in {@code VaultInitializer}, which writes and reads these rows.
     */
    private static final String CREATE_VAULT_META = """
            CREATE TABLE vault_meta (
                key   TEXT PRIMARY KEY,
                value ANY NOT NULL
            ) STRICT
            """;

    /**
     * One row per stored secret. {@code name} identifies the entry to the user and is unique, which
     * gives it an index for free; {@code username} is kept in the clear so entries can be listed
     * without the master password.
     *
     * <p>Only the secret itself is encrypted, under the DEK, with its own {@code iv} — never a
     * shared one, since reusing an IV under the same key breaks AES-GCM outright.
     *
     * <p>Timestamps are epoch milliseconds. SQLite has no date type, so something had to be chosen;
     * an integer sorts and compares correctly and carries no timezone question.
     */
    private static final String CREATE_ENTRIES = """
            CREATE TABLE entries (
                id         INTEGER PRIMARY KEY,
                name       TEXT NOT NULL UNIQUE,
                username   TEXT,
                iv         BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            ) STRICT
            """;

    private SchemaInitializer() {
    }

    /**
     * Creates the vault's tables on {@code connection}.
     *
     * <p>Expects an empty database and does not use {@code IF NOT EXISTS}: a vault is created once,
     * and a file that already holds these tables is an existing vault rather than something to add
     * to. Running this twice therefore fails, which is the honest outcome.
     *
     * <p>Runs inside the caller's transaction and neither commits nor rolls back. SQLite can roll
     * back {@code CREATE TABLE}, so a failure later in the same transaction leaves no tables behind.
     */
    public static void createSchema(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute(CREATE_VAULT_META);
            statement.execute(CREATE_ENTRIES);
        }
    }
}
