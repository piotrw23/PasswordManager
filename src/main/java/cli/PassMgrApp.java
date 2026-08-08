package cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Spec;

import java.util.concurrent.Callable;

@Command(name = "pass-mgr",
        subcommands = {GenerateCommand.class},
        mixinStandardHelpOptions = true,
        version = "1.0")
public class PassMgrApp implements Callable<Integer> {

    @Spec
    private CommandSpec spec;

    public static void main(String[] args) {
        // We pass arguments from command line to Picocli and return exit code
        int exitCode = new CommandLine(new PassMgrApp()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() {
        spec.commandLine().usage(System.out);
        return 0;
    }
}