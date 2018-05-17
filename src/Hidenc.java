import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

/**
 * Klassen tar in data i angiven inputfil och placerar i en blob. Bloben krypteras och placeras i annan data och skrivs
 * sedan till angiven outputfil.
 * Krypterar med AES-CTR och AES-ECB
 * Created by mikaelnorberg on 2017-05-21.
 */
public class Hidenc {
    private final int BLOCK_SIZE = 16;

    private byte[] blob;

    private byte[] key;
    private byte[] keyHash;

    private byte[] input;
    private byte[] inputHash;

    private byte[] ctr;

    private byte[] template;
    private int size;

    private boolean OFFSET = false;
    private boolean SIZE = false;
    private boolean TEMPLATE = false;
    private boolean CTR = false;

    private String keyInput;
    private String ctrInput;
    private String inputFile;
    private String outputFile;
    private String templateFile;
    private int offset;
    private byte[] output;

    private Hidenc (String[] args){
        processFlags(args);
        validateArgs();
        readFiles();
        this.keyHash = hashData(this.key);
        this.inputHash = hashData(this.input);
        if(this.CTR){
            ctr();
        } else {
            ecb();
        }
        writeFile(this.output, this.outputFile);
        System.out.println("Data har skrivits till filen " + this.outputFile);
        System.out.println("Programmet avslutas.");
    }
    private void ctr() {
        createBlob();
        if (this.TEMPLATE) {
            this.output = putBlobInTemplate(this.template);
        } else {
            byte[] randomTemplate = createRandomTemplate();
            this.output = putBlobInTemplate(randomTemplate);
        }
    }
    private void ecb() {
        createBlob();
        if (this.TEMPLATE) {
            this.output = putBlobInTemplate(this.template);
        } else {
            byte[] randomTemplate = createRandomTemplate();
            this.output = putBlobInTemplate(randomTemplate);
        }
    }

    private byte[] createRandomTemplate() {
        byte[] randomTemplate = new byte[this.size];
        randomTemplate = generateRandomArray(randomTemplate);
        return randomTemplate;
    }

    private byte[] generateRandomArray(byte[] randomTemplate) {
        Random random = new Random();
        random.nextBytes(randomTemplate);
        return randomTemplate;
    }


    private byte[] putBlobInTemplate(byte[] template) {
        int index = 0;
        if(this.OFFSET) {
            for (int i = this.offset; i < (this.offset + this.blob.length); i++) {
                template[i] = this.blob[index++];
            }
        } else {
            int randomOffset = generateRandomOffset();
            for (int i = randomOffset; i < (randomOffset + this.blob.length); i++) {
                template[i] = this.blob[index++];
            }
        }
        return template;
    }


    private int generateRandomOffset() {
        Random random = new Random();
        int randomNumber = 3;
        if (this.SIZE) {
            if(this.size == this.blob.length) {
                return 0;
            }
            while (randomNumber % this.BLOCK_SIZE != 0) {
                randomNumber = random.nextInt(this.size - this.blob.length);
            }
        } else {
            if(this.template.length == this.blob.length) {
                return 0;
            }
            while (randomNumber % this.BLOCK_SIZE != 0) {
                randomNumber = random.nextInt(this.template.length - this.blob.length);
            }
        }
        return randomNumber;
    }

    private void createBlob() {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(this.keyHash);
            outputStream.write(this.input);
            outputStream.write(this.keyHash);
            outputStream.write(this.inputHash);
            this.blob = outputStream.toByteArray();
            if(CTR){
                this.blob = encryptCTR(this.blob, this.key, this.ctr);
            } else {
                this.blob = encryptECB(this.blob, this.key);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }



    private byte[] encryptCTR(byte[] data, byte[] key, byte[] CTR) {
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        byte[] encrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            IvParameterSpec ivSpec = new IvParameterSpec(CTR);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            encrypted = cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return encrypted;
    }

    private byte[] encryptECB(byte[] data, byte[] key){
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        byte[] encrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            encrypted = cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return encrypted;
    }
    private byte[] hashData(byte[] data){
        MessageDigest MD;
        final String ALGORITHM = "MD5";
        try {
            MD = MessageDigest.getInstance(ALGORITHM);
            MD.update(data);
            return MD.digest();

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Algorithm \"" + ALGORITHM + "\" is not available");
        }
        return null;
    }
    private void readFiles() {
        if(this.SIZE || this.TEMPLATE) {
            this.key = stringToHex(this.keyInput);
            this.input = readFile(this.inputFile);
            validateInputLength(this.input);
            if (this.TEMPLATE) {
                this.template = readFile(this.templateFile);
                validateOffset(this.template.length);
                validateThatBlobFitsOutput(this.template.length);
            }
            if (this.CTR) {
                this.ctr = stringToHex(this.ctrInput);
            }
            if(this.SIZE) {
                validateOffset(this.size);
                validateThatBlobFitsOutput(this.size);
            }
        } else {
            printMessage(14);
        }
    }

    private byte[] stringToHex(String hexString){
        byte[] result = null;
        try {
            result = DatatypeConverter.parseHexBinary(hexString);
        } catch (IllegalArgumentException e) {
            printMessage(16);
        }
        return result;
    }



    private void validateOffset(int outputSize) {
        if (this.OFFSET){
            if(this.offset % this.BLOCK_SIZE != 0){
                printMessage(13);
            }
            if (outputSize < (this.offset + this.input.length)) {
                printMessage(3);
            }
        }
    }

    private void validateInputLength(byte[] encryptedInput) {
        if(encryptedInput.length % this.BLOCK_SIZE != 0){
            printMessage(9);
        }
    }
    private void validateThatBlobFitsOutput(int outputSize) {
        final int BLOB_PADDING_SIZE = 3 * this.BLOCK_SIZE;
        if (outputSize % this.BLOCK_SIZE != 0) {
            printMessage(12);
        }
        if (this.OFFSET) {
            if (outputSize < ((this.input.length + BLOB_PADDING_SIZE) + this.offset)) {
                printMessage(3);
            }
        } else {
            if (outputSize < (this.input.length + BLOB_PADDING_SIZE)) {
                printMessage(3);
            }
        }
    }

    private void writeFile(byte[] data, String outputFile) {
        try (FileOutputStream fos = new FileOutputStream(outputFile)){
            DataOutputStream output = new DataOutputStream(fos);
            output.write(data);
            output.close();
        } catch (FileNotFoundException e) {
            System.out.println("Kontrollera skrivrättigheter för " + outputFile + " och försök igen.");
            System.out.println("Dekryptering avbruten. Programmet avslutas.");
            System.exit(0);
        } catch (IOException f) {
            System.out.println("Något gick fel när encryptedInput skrevs till " + outputFile);
            System.out.println("Dekryptering avbruten. Programmet avslutas.");
            System.exit(0);
        }
    }

    private void printMessage(int message) {
        if (message == 0){
            System.out.println("Argumentet <size> måste vara ett positivt heltal större än 3.");
            System.out.println("Detta för att få plats med en hel blob.");
        } else if (message == 1) {
            System.out.println("Endast ett av argumenten <size> och <template> är tillåtet.");
        } else if (message == 2) {
            System.out.println("Argumentet <offset> måste vara ett positivt heltal större än eller lika med 0.");
        } else if (message == 3) {
            System.out.println("Blobben får inte plats i outputfilen.");
        } else if (message == 4) {

        } else if (message == 5) {
            System.out.println("Den inmatade nyckeln är 33 byte. Den 33e byten tas bort. Det är troligtvis en lineFeed.");
        } else if (message == 6) {
            System.out.println("Nyckel-input måste vara 32 eller 33 byte. om 33 så tas den sista byten bort.");
        } else if (message == 7) {
            System.out.println("Den inmatade CTR är 33 byte. Den 33e byten tas bort. Det är troligtvis en lineFeed.");
        } else if (message == 8) {
            System.out.println("CTR-input måste vara 32 eller 33 byte. om 33 så tas den sista byten bort.");
        } else if (message == 9) {
            System.out.println("datafilen måste vara en multipel av blockstorleken 128 bitar.");
        } else if (message == 10) {
            System.out.println("input får endast innehålla a-f, A-F och 0-9");
        } else if (message == 11) {
            System.out.println("Programmet har anropats med felaktiga argument.");
        } else if (message == 12) {
            System.out.println("Outputfilen måste vara en multipel av blockstorleken.");
        } else if (message == 13) {
            System.out.println("Blobben måste placeras på ett ställe i filen som är en multipel av blockstorleken.");
        } else if (message == 14) {
            System.out.println("Ett av argumenten <size> och <template> krävs.");
        } else if (message == 15) {
            System.out.println("Nyckel och Ctr måste vara 32 tecken lång");
        } else if (message == 16) {
            System.out.println("Nyckel och Ctr får endast innehålla tecken 0-9 och a-f.");
        }
        if(message != 5 && message != 7) {
            System.out.println("Försök igen. Programmet avslutas.");
            System.exit(0);
        }
    }
    private boolean validateArgs(){

        if(!((inputFile != null && inputFile.length() != 0) &&
                (outputFile != null && outputFile.length() != 0))) {
            printMessage(11);
        }
        if(this.TEMPLATE) {
            if(!(this.templateFile != null && this.templateFile.length() != 0)) {
                printMessage(11);
            }
        }
        return CTR;
    }

    private void processFlags(String[] args) {
        final String KEY_FLAG = "--key=";
        final String CTR_FLAG = "--ctr=";
        final String INPUT_FLAG = "--input=";
        final String OUTPUT_FLAG = "--output=";
        final String TEMPLATE_FLAG = "--template=";
        final String SIZE_FLAG = "--size=";
        final String OFFSET_FLAG = "--offset=";
        for (String arg : args) {
            if(arg.contains(KEY_FLAG)){
                this.keyInput = arg.substring(KEY_FLAG.length());
                if(this.keyInput.length() != 32) {
                    printMessage(15);
                }
            }else if(arg.contains(CTR_FLAG)){
                this.ctrInput = arg.substring(CTR_FLAG.length());
                if(this.ctrInput.length() != 32) {
                    printMessage(15);
                }
                this.CTR = true;
            }else if(arg.contains(INPUT_FLAG)){
                this.inputFile = arg.substring(INPUT_FLAG.length());
            }else if(arg.contains(OUTPUT_FLAG)){
                this.outputFile = arg.substring(OUTPUT_FLAG.length());
            }else if(arg.contains(TEMPLATE_FLAG)){
                if (this.SIZE) {
                    printMessage(1);
                }
                this.templateFile = arg.substring(TEMPLATE_FLAG.length());
                this.TEMPLATE = true;
            }else if(arg.contains(SIZE_FLAG)){
                if (this.TEMPLATE) {
                    printMessage(1);
                }
                try {
                    this.size = Integer.parseInt(arg.substring(SIZE_FLAG.length()));
                    if(this.size < 4) {
                        printMessage(0);
                    }
                } catch (NumberFormatException e) {
                    printMessage(0);
                }
                this.SIZE = true;
            }else if(arg.contains(OFFSET_FLAG)){
                try {
                    this.offset = Integer.parseInt(arg.substring(OFFSET_FLAG.length()));
                    if(this.offset < 0) {
                        printMessage(2);
                    }
                } catch (NumberFormatException e) {
                    printMessage(2);
                }
                this.OFFSET = true;
            } else {
                System.out.println("Programmet kan inte anropas med argumentet " + arg + ".");
                System.out.println("Programmet avslutas.");
                System.exit(0);
            }
        }

    }
    private byte[] readFile(String fileName){
        byte[] plainText = null;
        try (FileInputStream fis = new FileInputStream(fileName)){
            final int FILESIZE = (int) fis.getChannel().size();
            if(FILESIZE == 0){
                System.out.println("Filen " + fileName + " innehåller ingen data. Programmet avslutas");
                System.out.println();
                System.out.println("Kryptering avbruten. programmet avslutas");
                System.exit(0);
            }
            plainText = new byte[FILESIZE];
            DataInputStream input  = new DataInputStream(fis);
            for(int i = 0; i < plainText.length; i++) {
                plainText[i] = input.readByte();
            }
        } catch (FileNotFoundException e) {
            System.out.println("Filen " + fileName + " gick inte att öppna.");
            System.out.println("Kontrollera att filen finns och försök igen.");
            System.out.println();
            System.out.println("Programmet avslutas");
            System.exit(0);
        } catch (EOFException e) {
            System.out.println("Något gick fel vid läsning av " + fileName + ". Försök igen.");
            System.out.println();
            System.out.println("Programmet avslutas");
            System.exit(0);
        }catch (IOException e) {
            System.out.println("Något gick fel med filen " + fileName + ". Försök igen.");
            System.out.println();
            System.out.println("Programmet avslutas");
            System.exit(0);
        }
        if(plainText.length == 1) {
            System.out.println("Filen " + fileName + " innehåller ingen data. Programmet avslutas");
            System.out.println("Programmet avslutas");
            System.exit(0);
        }
        return plainText;
    }

    public static void main(String[] args) {
        if(args.length == 4 || args.length == 5 || args.length == 6){
            new Hidenc(args);
        } else {
            System.out.println("Programmet måste startas med fyra, fem eller sex argument.");
            System.out.println("Försök igen. Programmet avslutas.");
        }
    }
}
