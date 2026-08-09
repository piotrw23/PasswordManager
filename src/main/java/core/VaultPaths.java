package core;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

/**
 * Locates the vault directory and the files inside it.
 * The directory is owner-only, so no other user on the machine can read the encrypted vault.
 */
public final class VaultPaths {

    static final String VAULT_HOME_ENV = "PASS_MGR_HOME";
    static final String DEFAULT_DIRECTORY_NAME = ".pass-mgr";
    static final String DATABASE_FILE_NAME = "vault.db";

    private static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rwx------");

    private final Path vaultHome;

    public VaultPaths(Path vaultHome) {
        this.vaultHome = vaultHome.toAbsolutePath().normalize();
    }

    public static VaultPaths fromEnvironment() {
        return new VaultPaths(resolveVaultHome(System.getenv(VAULT_HOME_ENV), System.getProperty("user.home")));
    }

    // kept separate from fromEnvironment() so tests can exercise the resolution rules
    // without reading the environment or touching the real home directory
    static Path resolveVaultHome(String envValue, String userHome) {
        if (envValue != null && !envValue.isBlank()) {
            return Path.of(envValue.trim());
        }
        return Path.of(userHome, DEFAULT_DIRECTORY_NAME);
    }

    public Path vaultHome() {
        return vaultHome;
    }

    public Path databaseFile() {
        return vaultHome.resolve(DATABASE_FILE_NAME);
    }

    public boolean vaultExists() {
        return Files.isRegularFile(databaseFile());
    }

    /**
     * Creates the vault directory if it is missing. Does nothing when it is already there.
     */
    public void ensureVaultDirectory() throws IOException {
        requirePosixFileSystem();

        // permissions are passed to createDirectories so the directory is never
        // world-readable, not even for the moment between creating and chmod-ing it
        FileAttribute<Set<PosixFilePermission>> ownerOnly = PosixFilePermissions.asFileAttribute(OWNER_ONLY);
        try {
            Files.createDirectories(vaultHome, ownerOnly);
        } catch (FileAlreadyExistsException e) {
            throw new IOException(vaultHome + " already exists and is not a directory", e);
        }
    }

    /**
     * Tells whether the vault directory is readable only by its owner. An existing directory
     * keeps whatever permissions it was created with, so this is worth checking before use.
     */
    public boolean hasSecurePermissions() throws IOException {
        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(vaultHome);
        return permissions.stream().noneMatch(VaultPaths::isGroupOrOthers);
    }

    private static boolean isGroupOrOthers(PosixFilePermission permission) {
        return permission.name().startsWith("GROUP_") || permission.name().startsWith("OTHERS_");
    }

    private static void requirePosixFileSystem() throws IOException {
        if (!FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            throw new IOException("pass-mgr needs a POSIX filesystem to keep the vault private to your user account");
        }
    }
}
