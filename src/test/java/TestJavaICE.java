import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestJavaICE {

    // START CERTIFICATION TRIPLETS

    @Test
    public void testEncrypt_ICE() {
        byte[] plaintext = {
                (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10
        };
        byte[] key = {
                (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67
        };
        byte[] expectedCiphertext = {
                (byte) 0x7d, (byte) 0x6e, (byte) 0xf1, (byte) 0xef, (byte) 0x30, (byte) 0xd4, (byte) 0x7a, (byte) 0x96
        };

        byte[] actualCiphertext = JavaICE.encrypt(plaintext, 1, key);

        assertArrayEquals(expectedCiphertext, actualCiphertext);
    }

    @Test
    public void testDecrypt_ICE() {
        byte[] plaintext = {
                (byte) 0x7d, (byte) 0x6e, (byte) 0xf1, (byte) 0xef, (byte) 0x30, (byte) 0xd4, (byte) 0x7a, (byte) 0x96
        };
        byte[] expectedPlaintext = {
                (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10
        };
        byte[] key = {
                (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67
        };

        byte[] actualPlaintext = JavaICE.decrypt(plaintext, 1, key);

        assertArrayEquals(expectedPlaintext, actualPlaintext);
    }


    @Test
    public void testEncrypt_ThinICE() {
        byte[] plaintext = {
                (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10
        };
        byte[] key = {
                (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67
        };
        byte[] expectedCiphertext = {
                (byte) 0xde, (byte) 0x24, (byte) 0x0d, (byte) 0x83, (byte) 0xa0, (byte) 0x0a, (byte) 0x9c, (byte) 0xc0
        };

        byte[] actualCiphertext = JavaICE.encrypt(plaintext, 0, key);

        assertArrayEquals(expectedCiphertext, actualCiphertext);
    }

    @Test
    public void testDecrypt_ThinICE() {
        byte[] ciphertext = {
                (byte) 0xde, (byte) 0x24, (byte) 0x0d, (byte) 0x83, (byte) 0xa0, (byte) 0x0a, (byte) 0x9c, (byte) 0xc0
        };
        byte[] key = {
                (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67
        };
        byte[] expectedPlaintext = {
                (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10
        };

        byte[] actualPlaintext = JavaICE.decrypt(ciphertext, 0, key);

        assertArrayEquals(expectedPlaintext, actualPlaintext);
    }


    @Test
    public void testEncrypt_ICE2() {
        byte[] plaintext = {
                (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10
        };
        byte[] key = {
                (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff
        };
        byte[] expectedCiphertext = {
                (byte) 0xf9, (byte) 0x48, (byte) 0x40, (byte) 0xd8, (byte) 0x69, (byte) 0x72, (byte) 0xf2, (byte) 0x1c
        };

        byte[] actualCiphertext = JavaICE.encrypt(plaintext, 2, key);

        assertArrayEquals(expectedCiphertext, actualCiphertext);
    }

    @Test
    public void testDecrypt_ICE2() {
        byte[] ciphertext = {
                (byte) 0xf9, (byte) 0x48, (byte) 0x40, (byte) 0xd8, (byte) 0x69, (byte) 0x72, (byte) 0xf2, (byte) 0x1c
        };
        byte[] key = {
                (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff
        };
        byte[] expectedPlaintext = {
                (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10
        };

        byte[] actualPlaintext = JavaICE.decrypt(ciphertext, 2, key);

        assertArrayEquals(expectedPlaintext, actualPlaintext);
    }

    // END CERTIFICATION TRIPLETS


    @Test
    void testStringInput() {
        byte[] key = {
                (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67
        };

        String expectedPlaintext = "Hello ICE world!";
        byte[] ciphertext = JavaICE.encrypt(expectedPlaintext, 1, key);
        String actualPlaintext = new String(JavaICE.decrypt(ciphertext, 1, key));

        assertEquals(expectedPlaintext, actualPlaintext);
    }


    @Test
    void testEncryptNon64Multiple() {
        byte[] plaintext = {
                (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10, (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10
        };
        byte[] key = {
                (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67
        };

        byte[] ciphertext = JavaICE.encrypt(plaintext, 1, key);
        byte[] actualPlaintext = JavaICE.decrypt(ciphertext, 1, key);

        assertArrayEquals(plaintext, actualPlaintext);
    }
}
