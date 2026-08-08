// Decompile selected functions for AIDebug's bounded headless integration.
//@category AIDebug

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class AIDebugDecompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 5) {
            throw new IllegalArgumentException(
                "Expected output directory, address list, original image base, " +
                "function timeout, and character limit"
            );
        }

        Path outputDirectory = Path.of(arguments[0]).toAbsolutePath().normalize();
        Path addressList = Path.of(arguments[1]).toAbsolutePath().normalize();
        long originalImageBase = Long.parseLong(arguments[2]);
        int functionTimeout = Integer.parseInt(arguments[3]);
        int characterLimit = Integer.parseInt(arguments[4]);
        if (functionTimeout < 1 || functionTimeout > 300) {
            throw new IllegalArgumentException("Function timeout is outside the allowed range");
        }
        if (characterLimit < 512 || characterLimit > 1000000) {
            throw new IllegalArgumentException("Character limit is outside the allowed range");
        }

        Files.createDirectories(outputDirectory);
        Path errorLog = outputDirectory.resolve("errors.log");
        List<String> requestedAddresses = Files.readAllLines(addressList, StandardCharsets.US_ASCII);
        FunctionManager functionManager = currentProgram.getFunctionManager();
        AddressSpace addressSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();

        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(currentProgram);
        decompiler.setOptions(options);
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Ghidra decompiler could not open the imported program");
        }

        try {
            for (String requested : requestedAddresses) {
                monitor.checkCancelled();
                String addressText = requested.trim().toLowerCase();
                if (addressText.isEmpty()) {
                    continue;
                }
                try {
                    long offset = Long.parseUnsignedLong(addressText, 16);
                    long rebasedOffset = offset - originalImageBase +
                        currentProgram.getImageBase().getOffset();
                    Address address = addressSpace.getAddress(rebasedOffset);
                    Function function = functionManager.getFunctionAt(address);
                    if (function == null) {
                        function = functionManager.getFunctionContaining(address);
                    }
                    if (function == null) {
                        appendError(errorLog, addressText + ": function not identified");
                        continue;
                    }

                    DecompileResults result = decompiler.decompileFunction(
                        function,
                        functionTimeout,
                        monitor
                    );
                    if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                        appendError(
                            errorLog,
                            addressText + ": " + safeMessage(result.getErrorMessage())
                        );
                        continue;
                    }

                    String code = result.getDecompiledFunction().getC();
                    if (code == null || code.isBlank()) {
                        appendError(errorLog, addressText + ": empty decompiler output");
                        continue;
                    }
                    if (code.length() > characterLimit) {
                        String marker = "\n/* Ghidra output truncated by AIDebug safety limit */\n";
                        code = code.substring(0, Math.max(0, characterLimit - marker.length())) + marker;
                    }
                    Files.writeString(
                        outputDirectory.resolve(addressText + ".c"),
                        code,
                        StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE_NEW,
                        StandardOpenOption.WRITE
                    );
                }
                catch (Exception exception) {
                    appendError(
                        errorLog,
                        addressText + ": " + safeMessage(exception.getMessage())
                    );
                }
            }
        }
        finally {
            decompiler.dispose();
        }
    }

    private static void appendError(Path errorLog, String message) throws Exception {
        Files.writeString(
            errorLog,
            safeMessage(message) + System.lineSeparator(),
            StandardCharsets.UTF_8,
            StandardOpenOption.CREATE,
            StandardOpenOption.APPEND,
            StandardOpenOption.WRITE
        );
    }

    private static String safeMessage(String message) {
        if (message == null || message.isBlank()) {
            return "unknown decompiler error";
        }
        return message.replace('\r', ' ').replace('\n', ' ');
    }
}
