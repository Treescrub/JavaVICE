import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestJavaVICE {

    private static byte[] getByteArray(int... bytes) {
        byte[] byteArray = new byte[bytes.length];
        for(int i = 0; i < bytes.length; i++) {
            byteArray[i] = (byte) bytes[i];
        }
        return byteArray;
    }

    @Test
    public void certTripletICE_encrypt() {
        byte[] plaintext = getByteArray(0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10);
        byte[] key = getByteArray(0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67);
        byte[] expectedCiphertext = getByteArray(0x7D, 0x6E, 0xF1, 0xEF, 0x30, 0xD4, 0x7A, 0x96);

        byte[] actualCiphertext = JavaVICE.encrypt(new Key(key, 1), plaintext);

        assertArrayEquals(expectedCiphertext, actualCiphertext);
    }

    @Test
    public void certTripletICE_decrypt() {
        byte[] ciphertext = getByteArray(0x7D, 0x6E, 0xF1, 0xEF, 0x30, 0xD4, 0x7A, 0x96);
        byte[] key = getByteArray(0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67);
        byte[] expectedPlaintext = getByteArray(0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10);

        byte[] actualPlaintext = JavaVICE.decrypt(new Key(key, 1), ciphertext);

        assertArrayEquals(expectedPlaintext, actualPlaintext);
    }

    @Test
    public void certTripletThinICE_encrypt() {
        byte[] plaintext = getByteArray(0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10);
        byte[] key = getByteArray(0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67);
        byte[] expectedCiphertext = getByteArray(0xDE, 0x24, 0x0D, 0x83, 0xA0, 0x0A, 0x9C, 0xC0);

        byte[] actualCiphertext = JavaVICE.encrypt(new Key(key, 0), plaintext);

        assertArrayEquals(expectedCiphertext, actualCiphertext);
    }

    @Test
    public void certTripletThinICE_decrypt() {
        byte[] ciphertext = getByteArray(0xDE, 0x24, 0x0D, 0x83, 0xA0, 0x0A, 0x9C, 0xC0);
        byte[] key = getByteArray(0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67);
        byte[] expectedPlaintext = getByteArray(0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10);

        byte[] actualPlaintext = JavaVICE.decrypt(new Key(key, 0), ciphertext);

        assertArrayEquals(expectedPlaintext, actualPlaintext);
    }

    @Test
    public void certTripletICE2_encrypt() {
        byte[] plaintext = getByteArray(0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10);
        byte[] key = getByteArray(0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        byte[] expectedCiphertext = getByteArray(0xF9, 0x48, 0x40, 0xD8, 0x69, 0x72, 0xF2, 0x1C);

        byte[] actualCiphertext = JavaVICE.encrypt(new Key(key, 2), plaintext);

        assertArrayEquals(expectedCiphertext, actualCiphertext);
    }

    @Test
    public void certTripletICE2_decrypt() {
        byte[] ciphertext = getByteArray(0xF9, 0x48, 0x40, 0xD8, 0x69, 0x72, 0xF2, 0x1C);
        byte[] key =  getByteArray(0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        byte[] expectedPlaintext = getByteArray(0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10);

        byte[] actualPlaintext = JavaVICE.decrypt(new Key(key, 2), ciphertext);

        assertArrayEquals(expectedPlaintext, actualPlaintext);
    }

    @Test
    void encryptUnaligned() {
        byte[] plaintext = getByteArray(0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x76, 0x54, 0x32, 0x10);
        byte[] key = getByteArray(0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67);
        byte[] expectedCiphertext = getByteArray(0x7D, 0x6E, 0xF1, 0xEF, 0x30, 0xD4, 0x7A, 0x96, 0x76, 0x54, 0x32, 0x10);

        byte[] ciphertext = JavaVICE.encrypt(new Key(key, 1), plaintext);

        assertArrayEquals(expectedCiphertext, ciphertext);
    }

    @Test
    void decryptUnaligned() {
        byte[] ciphertext = getByteArray(0x7D, 0x6E, 0xF1, 0xEF, 0x30, 0xD4, 0x7A, 0x96, 0x76, 0x54, 0x32, 0x10);
        byte[] key = getByteArray(0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67);
        byte[] expectedPlaintext = getByteArray(0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x76, 0x54, 0x32, 0x10);

        byte[] plaintext = JavaVICE.decrypt(new Key(key, 1), ciphertext);

        assertArrayEquals(expectedPlaintext, plaintext);
    }

    @Test
    void stringEncryptDecrypt() {
        String expectedPlaintext = "Hello ICE world!";
        byte[] key = getByteArray(0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67);
        byte[] ciphertext = JavaVICE.encrypt(new Key(key, 1), expectedPlaintext);

        String actualPlaintext = new String(JavaVICE.decrypt(new Key(key, 1), ciphertext));

        assertEquals(expectedPlaintext, actualPlaintext);
    }
}
