import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;

public class JavaICE {

    public static byte[] decrypt(Key key, byte[] data) {
        byte[] plaintext = new byte[data.length];

        int blockSize = key.getBlockSize();

        for(int i = 0, bytesLeft = plaintext.length; bytesLeft > 0; i += blockSize, bytesLeft -= blockSize) {
            if(bytesLeft < blockSize) {
                System.arraycopy(data, data.length - bytesLeft, plaintext, i, bytesLeft);
                break;
            }

            byte[] plaintextBlock = key.decryptBlock(Arrays.copyOfRange(data, i, i + blockSize));

            System.arraycopy(plaintextBlock, 0, plaintext, i, plaintextBlock.length);
        }

        return plaintext;
    }

    public static byte[] decrypt(Key key, String data) {
        return decrypt(key, data.getBytes());
    }

    public static byte[] decryptFromFile(Key key, Path path) throws IOException {
        return decrypt(key, Files.readAllBytes(path));
    }

    public static byte[] decryptFromFile(Key key, File file) throws IOException {
        return decryptFromFile(key, file.toPath());
    }

    public static CompletableFuture<byte[]> decryptAsync(Key key, byte[] data) {
        return CompletableFuture.supplyAsync(() -> decrypt(key, data));
    }

    public static CompletableFuture<byte[]> decryptAsync(Key key, String data) {
        return CompletableFuture.supplyAsync(() -> decrypt(key, data));
    }



    public static byte[] encrypt(Key key, byte[] data) {
        byte[] ciphertext = new byte[data.length];

        int blockSize = key.getBlockSize();

        for(int i = 0, bytesLeft = ciphertext.length; bytesLeft > 0; i += blockSize, bytesLeft -= blockSize) {
            if(bytesLeft < blockSize) {
                System.arraycopy(data, data.length - bytesLeft, ciphertext, i, bytesLeft);
                break;
            }

            byte[] ciphertextBlock = key.encryptBlock(Arrays.copyOfRange(data, i, i + blockSize));

            System.arraycopy(ciphertextBlock, 0, ciphertext, i, ciphertextBlock.length);
        }

        return ciphertext;
    }

    public static byte[] encrypt(Key key, String data) {
        return encrypt(key, data.getBytes());
    }

    public static byte[] encryptFromFile(Key key, Path path) throws IOException {
        return encrypt(key, Files.readAllBytes(path));
    }

    public static byte[] encryptFromFile(Key key, File file) throws IOException {
        return encryptFromFile(key, file.toPath());
    }

    public static CompletableFuture<byte[]> encryptAsync(Key key, byte[] data) {
        return CompletableFuture.supplyAsync(() -> encrypt(key, data));
    }

    public static CompletableFuture<byte[]> encryptAsync(Key key, String data) {
        return CompletableFuture.supplyAsync(() -> encrypt(key, data));
    }
}
