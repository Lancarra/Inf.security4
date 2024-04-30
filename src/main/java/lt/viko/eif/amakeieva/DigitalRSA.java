package lt.viko.eif.amakeieva;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class DigitalRSA {
    private static final String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789 ";
    private static BigInteger n;
    private static BigInteger e;
    private static BigInteger d;
    private static BigInteger p;  // Объявление статической переменной
    private static BigInteger q;  // Объявление статической переменной

    public static void main(String[] args) throws Exception {
        setupRSA();
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

        System.out.print("Enter text to sign: ");
        String textToSign = reader.readLine().toLowerCase();
        String signature = generateSignature(textToSign);
        System.out.println("Digital Signature: " + signature);

        sendOverSocket(textToSign, signature);
    }

    private static void setupRSA() {
        p = BigInteger.valueOf(61);
        q = BigInteger.valueOf(53);
        n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = new BigInteger("17");
        while (!phi.gcd(e).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.TWO);
        }
        d = e.modInverse(phi);

        checkKeys();

        System.out.println("Public Key (e, n): " + e.toString() + ", " + n.toString());
        System.out.println("Private Key (d, n): " + d.toString() + ", " + n.toString());
    }

    private static void checkKeys() {
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        BigInteger check = d.multiply(e).mod(phi);
        System.out.println("Check d * e mod phi(n) = 1: " + check.toString());
        if (!check.equals(BigInteger.ONE)) {
            throw new IllegalArgumentException("Keys are not correct: d and e are not inverses modulo phi(n)");
        }
    }

    private static String generateSignature(String message) {
        try {
            StringBuilder sb = new StringBuilder();
            for (char character : message.toCharArray()) {
                BigInteger charInt = BigInteger.valueOf((int) character);
                BigInteger encryptedChar = charInt.modPow(d, n);
                sb.append(encryptedChar.toString());
                sb.append(' ');  // Добавляем пробел между значениями
            }
            if (sb.length() > 0) {
                sb.deleteCharAt(sb.length() - 1);
            }
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void sendOverSocket(String message, String signature) throws IOException {
        try (Socket socket = new Socket("localhost", 7070)) {
            PrintWriter output = new PrintWriter(socket.getOutputStream(), true);
            output.println(e.toString() + "," + n.toString());  // Отправка открытого ключа
            output.println(message);
            output.println(signature);
        } catch (IOException e) {
            System.out.println("Could not connect to the server: " + e.getMessage());
            throw e;
        }
    }
}
