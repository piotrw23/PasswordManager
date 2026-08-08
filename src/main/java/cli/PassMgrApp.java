package cli;

import core.PasswordGenerator;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.Arrays;
import java.util.concurrent.Callable;

@Command(name = "pass-mgr",
        subcommands = {GenerateCommand.class},
        mixinStandardHelpOptions = true,
        version = "1.0")
public class PassMgrApp implements Callable<Integer> {

    @Option(names = {"-g", "--generate"}, description = "Generate new strong password.")
    private boolean generate;

    @Option(names = {"-l", "--length"}, description = "Length of genereted password.", defaultValue = "16")
    private int length;

    public static void main(String[] args) {
        // Przekazujemy argumenty z terminala do Picocli i zwracamy exit code
        int exitCode = new CommandLine(new PassMgrApp()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        // Główna logika programu
        if (generate) {
            System.out.println("Generating password...");
            PasswordGenerator generator = new PasswordGenerator();

            char[] newPassword = generator.generatePassword(length);
            double entropy = generator.computeEntropy(newPassword.length);

            System.out.println(newPassword);
            System.out.println("Password's entropy: " + entropy);
            Arrays.fill(newPassword, '\0');
        } else {
            System.out.println("Witaj w Pass-Mgr! Użyj --help, aby zobaczyć dostępne opcje.");
        }

        return 0;
    }
}