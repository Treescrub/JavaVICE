import picocli.CommandLine;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;

@CommandLine.Command(mixinStandardHelpOptions = true, version = "1.0", showDefaultValues = true)
public class JICE implements Runnable {

    @CommandLine.ArgGroup(exclusive = true, multiplicity = "1")
    Mode mode;

    static class Mode {
        @CommandLine.Option(names = {"-e", "--encrypt"}, description = "Encrypt the files") boolean encrypt;
        @CommandLine.Option(names = {"-d", "--decrypt"}, description = "Decrypt the files") boolean decrypt;
    }

    @CommandLine.Option(names = "--key", required = true, description = "Key used for encryption or decryption", paramLabel = "KEY") String key;
    @CommandLine.Option(names = "--level", defaultValue = "0", description = "ICE level", paramLabel = "<0|1|2>") int level;

    @CommandLine.Option(names = {"-r", "--recursive"}, description = "Recursively encrypt/decrypt files") boolean recursive;

    @CommandLine.Option(names = {"--out", "--output"}, paramLabel = "OUT_FOLDER", defaultValue = ".", description = "Output folder for encrypted/decrypted files") File outputDirectory;

    @CommandLine.Option(names = {"--ext", "--extension"}, defaultValue = ".out", description = "Extension to use for output") String extension;

    @CommandLine.Parameters(paramLabel = "FILES", description = "Files or directories to encrypt or decrypt", arity = "1..")
    File[] files;

    public static void main(String[] args) {
        new CommandLine(new JICE()).execute(args);
    }

    @Override
    public void run() {
        Key ICEKey = new Key(key, level);

        List<File> allFiles = findAllFiles(files);

        for(File file : allFiles) {
            try {
                byte[] outputBytes;
                if(mode.decrypt) {
                    outputBytes = JavaICE.decryptFromFile(ICEKey, file);
                } else {
                    outputBytes = JavaICE.encryptFromFile(ICEKey, file);
                }

                String newFileName = getNewFileName(file.getName());
                File outputFile = outputDirectory.toPath().resolve(newFileName).toFile();

                try(FileOutputStream outputStream = new FileOutputStream(outputFile)) {
                    outputStream.write(outputBytes);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private String getNewFileName(String fileName) {
        String newFileName = fileName;
        int extensionStartIndex = fileName.lastIndexOf(".");
        if(extension != null && !extension.isBlank()) {
            if (extensionStartIndex != -1) {
                newFileName = fileName.substring(0, extensionStartIndex) + extension;
            } else {
                newFileName = fileName + extension;
            }
        }

        return newFileName;
    }

    private List<File> findAllFiles(File[] initialFiles) {
        List<File> allFiles = new ArrayList<>(); // could cause memory allocation issues with very large file counts, switch to a linked list if it does cause issues
        Queue<File> fileQueue = new ArrayDeque<>(Arrays.asList(initialFiles));

        while(!fileQueue.isEmpty()) {
            File file = fileQueue.poll();

            if(file.isDirectory()) {
                if(recursive) {
                    fileQueue.addAll(Arrays.asList(file.listFiles()));
                }
                continue;
            }

            allFiles.add(file);
        }

        return allFiles;
    }
}
