import java.nio.charset.Charset;
import java.util.Arrays;

public class JavaICE {

    public static byte[] decrypt(String data, int level, byte[] key) {
        return decrypt(data.getBytes(), level, key);
    }

    public static byte[] decrypt(byte[] data, int level, byte[] key) {
        ICEKey iceKey = new ICEKey(level);
        iceKey.set(key);
        return decrypt(data, iceKey);
    }

    public static byte[] decrypt(byte[] data, ICEKey iceKey) {
        long bytesLeft = data.length;
        byte[] plaintext = new byte[data.length];

        for(int i = 0; bytesLeft > 0; i += iceKey.blockSize(), bytesLeft -= iceKey.blockSize()) {
            int endIndex =  bytesLeft < iceKey.blockSize() ? i + iceKey.blockSize() : plaintext.length;
            byte[] plaintext_sub = Arrays.copyOfRange(plaintext, i, endIndex);
            iceKey.decrypt(Arrays.copyOfRange(data, i, i + iceKey.blockSize()), plaintext_sub);

            System.arraycopy(plaintext_sub, 0, plaintext, i, plaintext_sub.length);
        }

        return plaintext;
    }

    public static byte[] encrypt(String data, int level, byte[] key) {
        return encrypt(data.getBytes(), level, key);
    }

    public static byte[] encrypt(byte[] data, int level, byte[] key) {
        ICEKey iceKey = new ICEKey(level);
        iceKey.set(key);
        return encrypt(data, iceKey);
    }

    public static byte[] encrypt(byte[] data, ICEKey iceKey) {
        int bytesLeft = data.length;

        byte[] ciphertext = new byte[data.length];

        for(int i = 0; bytesLeft > 0; i += iceKey.blockSize(), bytesLeft -= iceKey.blockSize()) {
            int endIndex =  bytesLeft < iceKey.blockSize() ? i + iceKey.blockSize() : data.length;
            byte[] ciphertext_sub = Arrays.copyOfRange(ciphertext, i, endIndex);
            iceKey.encrypt(Arrays.copyOfRange(data, i, i + iceKey.blockSize()), ciphertext_sub);

            System.arraycopy(ciphertext_sub, 0, ciphertext, i, ciphertext_sub.length);
        }

        return ciphertext;
    }
}
