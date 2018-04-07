import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Scanner;

public class Utils {
    private static Utils _singleton = null;

    public String filesPath;

    public static Utils instance() {
        if (_singleton == null) {
            _singleton = new Utils();
        }
        return _singleton;
    }

    public void clearConsole() {
        try {
            if (System.getProperty("os.name").contains("Windows")) {
                Runtime.getRuntime().exec("cls");
            } else {
                Runtime.getRuntime().exec("clear");
            }
        } catch (Exception e) {
        }
    }

    public boolean saveConsoleToFile() {
        System.out
                .println("Write the text of the file \n(Write 'fin' in a single line to end)");
        String text = "", line = "";
        Scanner scan = new Scanner(System.in);
        try {
            while (!line.equals("fin")) {

                line = scan.nextLine().toLowerCase();
                if (!line.equals("fin")) {
                    text = text + line + "\n";
                }
            }
            // scan.close();
            return saveFile("txt", text.getBytes());
        } catch (Exception e) {
            scan.close();
            System.out.println("Error: " + e);
            return false;
        }

    }

    protected Utils() {
        // Get files directory path
        filesPath = System.getProperty("user.dir") + "/files/";
    }

    public boolean saveFile(String ext, byte[] data) {
        System.out
                .print("Write the name of the file to store \n(it will be stored with extension "
                        + ext + "):");
        String fileName = new Scanner(System.in).nextLine();
        if (fileName.trim().length() == 0) {
            saveFile(ext, data);
        }
        String filePath = filesPath + fileName + "." + ext;
        try {
            BufferedOutputStream keystream = new BufferedOutputStream(
                    new FileOutputStream(filePath));
            keystream.write(data, 0, data.length);
            keystream.flush();
            keystream.close();
        } catch (Exception e) {
            System.out
                    .println("** Error while storing file '"
                            + filePath + "'\n");
            e.printStackTrace();
            return false;
        }
        System.out.println("File stored in " + filePath + "\n");
        return true;
    }

    public String readTextFromConsole(String message) {
        if (message != null) {
            System.out.print(message + ":");
        }
        return new Scanner(System.in).nextLine();
    }

    public byte[] loadFile(String infile) {
        try {
            // read the key, and decode from hex encoding
            BufferedInputStream keystream = new BufferedInputStream(
                    new FileInputStream(infile));
            int len = keystream.available();
            byte[] keyhex = new byte[len];
            keystream.read(keyhex, 0, len);
            return keyhex;
        } catch (Exception e) {
            System.err.println("** Error reading the file ");
            e.printStackTrace();
            return null;
        }
    }

    public byte[] doSelectFile(String message, final String extension) {
        File dir = new File(filesPath);

        File[] files = dir.listFiles(new FilenameFilter() {
            public boolean accept(File dir, String filename) {
                return filename.endsWith(extension);
            }
        });
        if (files.length == 0) {
            System.out
                    .println("** There is no file with extension "
                            + extension);
            return null;
        }
        for (File file : files) {
            System.out.println("\t- " + file.getName());
        }
        String fileName = readTextFromConsole(message);
        if (new File(filesPath + fileName).exists()) {
            return loadFile(filesPath + fileName);
        }
        if (new File(filesPath + fileName + "." + extension).exists()) {
            return loadFile(filesPath + fileName + "." + extension);
        } else {

            System.out.println("** File not found");
            return null;
        }
    }
}