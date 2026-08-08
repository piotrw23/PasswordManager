package cli;

import picocli.CommandLine;

import java.util.concurrent.Callable;

@CommandLine.Command(name = "generate", description = "Generates new strong password")
public class GenerateCommand implements Callable<Integer> {

    @CommandLine.Option(names = {"-l", "--length"}, description = "Length of genereted password")
    private int length;

    @Override
    public Integer call() throws Exception {
        if(length < 8) {
            System.err.println("Error: Password must have length at least 8");
            return 1;
        }

        System.out.println("Generating password of length" + length);
        return 0;
    }
}
