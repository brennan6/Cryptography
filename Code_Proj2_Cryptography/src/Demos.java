import java.util.Scanner;

import org.bouncycastle.util.encoders.Hex;

public class Demos {

    public static void main(String[] args) {
        Demos instance = new Demos();
        instance.doMenu();
    }

    /**
     * Menu options
     */
    protected final int MENU_OPTION_CREATE_FILE = 0;
    protected final int MENU_OPTION_GENERATE_DES_KEY = 1;
    protected final int MENU_OPTION_ENCRYPT_DES = 2;
    protected final int MENU_OPTION_DECRYPT_DES = 3;
    protected final int MENU_OPTION_GENERATE_AES_KEY = 4;
    protected final int MENU_OPTION_ENCRYPT_AES = 5;
    protected final int MENU_OPTION_DECRYPT_AES = 6;
    protected final int MENU_OPTION_CREATE_MD5 = 7;
    protected final int MENU_OPTION_CREATE_SHA1 = 8;
    protected final int MENU_OPTION_GENERATE_RSA_KEYS = 9;
    protected final int MENU_OPTION_ENCRYPT_RSA = 10;
    protected final int MENU_OPTION_DECRYPT_RSA = 11;

    /**
     * Muestra el menú y gestiona las solicitudes de cada una de sus opciones
     */
    private void doMenu() {
        System.out
                .println("\n\nAssignment of crypto algorithms with Java and BouncyCastle");
        System.out
                .println("----------------------------------------------------------------");
        System.out.println("\t  0. Create a text file");
        System.out.println("DES");
        System.out
                .println("\t  1. Create key for DES");
        System.out.println("\t  2. Encrypt file with DES");
        System.out.println("\t  3. Decrypt file with DES");
        System.out.println("AES");
        System.out
                .println("\t  4. Create key for AES");
        System.out.println("\t  5. Encrypt file with AES");
        System.out.println("\t  6. Decrypt file with AES");
        System.out.println("HASH FUNCTIONS");
        System.out.println("\t  7. Calculate MD5 of a file");
        System.out.println("\t  8. Calculate SHA1 of a file");
        System.out.println("RSA");
        System.out.println("\t  9. Create RSA keypair");
        System.out.println("\t 10. Encrypt file with RSA");
        System.out.println("\t 11. Decrypt file with RSA");
        System.out.println("\n q. Exit");
        System.out.print("\n\nChoose an option and press ENTER:");
        Scanner scanner = new Scanner(System.in);
        String selectedOption = scanner.nextLine();

        if (!selectedOption.matches("-?\\d+?") && !selectedOption.equals("q")) {
            System.out.println("Invalid choice");
        } else {
            if(selectedOption.equals("q")){
                System.exit(0);
            }
            switch (Integer.parseInt(selectedOption)) {
                case MENU_OPTION_CREATE_FILE:
                    Utils.instance().saveConsoleToFile();
                    break;
                case MENU_OPTION_GENERATE_DES_KEY:
                    new DES().doGenerateKey();
                    break;
                case MENU_OPTION_ENCRYPT_DES:
                    new DES().doEncrypt();
                    break;
                case MENU_OPTION_DECRYPT_DES:
                    new DES().doDecrypt();
                    break;
                case MENU_OPTION_GENERATE_AES_KEY:
                    new AES().doGenerateKey();
                    break;
                case MENU_OPTION_ENCRYPT_AES:
                    new AES().doEncrypt();
                    break;
                case MENU_OPTION_DECRYPT_AES:
                    new AES().doDecrypt();
                    break;
                case MENU_OPTION_CREATE_MD5:
                    new Hash().doMD5();
                    break;
                case MENU_OPTION_CREATE_SHA1:
                    new Hash().doSHA1();
                    break;
                case MENU_OPTION_GENERATE_RSA_KEYS:
                    new RSA().doGenerateKeys();
                    break;
                case MENU_OPTION_ENCRYPT_RSA:
                    new RSA().doEncrypt();
                    break;
                case MENU_OPTION_DECRYPT_RSA:
                    new RSA().doDecrypt();
                    break;
                default:
                    System.out.println("Invalid choice");
                    break;
            }
        }
        Utils.instance().clearConsole();
        doMenu();
    }
}
