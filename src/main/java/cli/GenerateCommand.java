package cli;

import core.PasswordGenerator;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.Arrays;
import java.util.concurrent.Callable;

@Command(name = "generate",
        description = "Generates new strong password",
        mixinStandardHelpOptions = true)
public class GenerateCommand implements Callable<Integer> {

    @Option(names = {"-l", "--length"},
            description = "Length of genereted password",
            defaultValue = "16")
    private int length;

    @Override
    public Integer call() throws Exception {
        if(length < 8) {
            System.err.println("Error: Password must have length at least 8");
            return 1;
        }

        PasswordGenerator generator = new PasswordGenerator();
        char[] newPassword = generator.generatePassword(length);
        try{
            System.out.println("Generated password:");
            System.out.println(newPassword);
            System.out.println("Password's entropy: " + generator.computeEntropy(length));
        } finally {
            Arrays.fill(newPassword, '\0');
        }
        return 0;
    }
}
