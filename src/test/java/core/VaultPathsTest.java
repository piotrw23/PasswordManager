package core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VaultPathsTest {

    @Test
    void usesEnvironmentVariableWhenItIsSet() {
        Path resolved = VaultPaths.resolveVaultHome("/opt/vaults/work", "/home/tester");
        assertEquals(Path.of("/opt/vaults/work"), resolved);
    }

    @Test
    void fallsBackToHomeDirectoryWhenEnvironmentVariableIsMissing() {
        assertEquals(Path.of("/home/tester/.pass-mgr"), VaultPaths.resolveVaultHome(null, "/home/tester"));
    }

    @Test
    void treatsBlankEnvironmentVariableAsUnset() {
        assertEquals(Path.of("/home/tester/.pass-mgr"), VaultPaths.resolveVaultHome("   ", "/home/tester"));
    }

    @Test
    void databaseSitsInsideTheVaultDirectory(@TempDir Path tempDir) {
        VaultPaths paths = new VaultPaths(tempDir);
        assertEquals(tempDir.resolve("vault.db"), paths.databaseFile());
    }

    @Test
    void createsVaultDirectoryReadableOnlyByItsOwner(@TempDir Path tempDir) throws IOException {
        VaultPaths paths = new VaultPaths(tempDir.resolve("vault-home"));

        paths.ensureVaultDirectory();

        assertTrue(Files.isDirectory(paths.vaultHome()));
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(paths.vaultHome())));
    }

    @Test
    void createsMissingParentDirectoriesAsOwnerOnly(@TempDir Path tempDir) throws IOException {
        Path nested = tempDir.resolve("outer/inner/vault-home");
        VaultPaths paths = new VaultPaths(nested);

        paths.ensureVaultDirectory();

        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(tempDir.resolve("outer"))));
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(nested)));
    }

    @Test
    void ensureVaultDirectoryCanBeCalledRepeatedly(@TempDir Path tempDir) throws IOException {
        VaultPaths paths = new VaultPaths(tempDir.resolve("vault-home"));

        paths.ensureVaultDirectory();
        paths.ensureVaultDirectory();

        assertTrue(Files.isDirectory(paths.vaultHome()));
    }

    @Test
    void failsWhenVaultHomeIsAFile(@TempDir Path tempDir) throws IOException {
        Path file = Files.createFile(tempDir.resolve("vault-home"));
        VaultPaths paths = new VaultPaths(file);

        IOException thrown = assertThrows(IOException.class, paths::ensureVaultDirectory);
        assertTrue(thrown.getMessage().contains("not a directory"));
    }

    @Test
    void vaultDoesNotExistUntilTheDatabaseFileIsThere(@TempDir Path tempDir) throws IOException {
        VaultPaths paths = new VaultPaths(tempDir.resolve("vault-home"));
        paths.ensureVaultDirectory();
        assertFalse(paths.vaultExists());

        Files.createFile(paths.databaseFile());

        assertTrue(paths.vaultExists());
    }

    @Test
    void detectsAVaultDirectoryOtherUsersCanReach(@TempDir Path tempDir) throws IOException {
        VaultPaths paths = new VaultPaths(tempDir.resolve("vault-home"));
        paths.ensureVaultDirectory();
        assertTrue(paths.hasSecurePermissions());

        Files.setPosixFilePermissions(paths.vaultHome(), PosixFilePermissions.fromString("rwxr-xr-x"));

        assertFalse(paths.hasSecurePermissions());
    }
}
