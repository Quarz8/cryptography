import java.io.*;
import java.util.Arrays;

public class AES128
{

    /**
     * 32 hex (0-f) characters (128 bits) per line in plaintext and key
     * last line of plaintext must get padded
     * 
     * Use ECB Electronic Code Book during encryption/decryption.
     * i.e. Each block is encoded separately
     * 
     * Read in a line, convert from hex to binary and store in state array
     * Apply AES algorithm to encrypt stored string, then write to output file in hex.
     * 
     * Pad input lines with <32 hex with 0s on right side
     * Input lines >32 hex are truncated to 32 hex. (i.e. ignore anything after 32nd hex char)
     * Upper/Lowercase shouldn't matter (so, set all uppercase or something) parseInt sees through cases
     * 
     * Book Sample for testing purposes
     * Plaintext: 0123456789abcdeffedcba9876543210
     * Key: 0f1571c947d9e8590cb7add6af7f6798
     * Ciphertext: ff0b844a0853bf7c6934ab4364148fb9
     * 
     * ENCRYPTION PROCESS
     * 0. In first round, simply add cipher key to state.
     * 1. Substitute bytes using s-box
     * 2. Shift rows left (first row by 0, second row by 1, third row by 2...)
     * 3. Mix columns (matrix multiplication of state columns with mixMatrix rows)
     * 4. Add round key (matrix addition, simply add (XOR) round key from key schedule to state matrix)
     * 5. Total of 11 rounds. Final round does NOT mix columns.
     * There is 1 initial round, 9 main rounds, and 1 final round
     * 
     * Note: Convert hex values to int and then XOR them. e.g. 
     * 
     * KEY SCHEDULE
     * 1. Every 4th column is shifted by 1, each byte is substituted by the s-box, the XOR with round constant AS WELL AS...
     * 2. EVERY (including every 4th) column is XOR with the i-4th column.
     * e.g. column i = column i-1 XOR column i-4.
     * e.g. every 4th column i = (column i-1 shifted by 1, subbed with s-box) XOR column i-4 XOR rcon column {rcon value, 0, 0, 0}
     * 
     * Note: Columns start at 0. So columns 4, 8, 12, etc. follow step 1 in key scheduling
     * 
     * Basic plan: For each hex line, convert to binary, apply AES operations, print hex to output file.
     */
    
    //binary conversion is literally pointless here just use decimal integers for math and hex strings for outputs and s-box, not binary strings
   // public String toBinary() {
   //     case 0
  //  }
    
    // 
    
    // Mixer array for encryptions
    static int[][] mixMatrix = {{0x02, 0x03, 0x01, 0x01},
            {0x01, 0x02, 0x03, 0x01},
            {0x01, 0x01, 0x02, 0x03},
            {0x03, 0x01, 0x01, 0x02}};
        
    // Rcon used for key scheduling, starts at 0x00 for some reason. guess its for round 0 (initial) since it doesnt use rcon
    static int[] rCon = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
            0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
            0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
            0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39};
    
    // S-box for substitutions
    static int[][] sBox = {
            {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
            {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
            {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
            {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
            {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
            {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
            {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
            {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
            {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
            {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
            {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
            {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
            {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
            {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
            {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
            {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
    };

    
    public static void main(String[] args) throws Exception
    {
        // File names
        File keyFile = new File("C:\\Users\\Warren\\Documents\\Adv Cryptography\\key.txt");
        File plainFile = new File("C:\\Users\\Warren\\Documents\\Adv Cryptography\\plaintext.txt");
        File cipherFile = new File("C:\\Users\\Warren\\Documents\\Adv Cryptography\\ciphertext.txt");
        
        BufferedReader key = new BufferedReader(new FileReader(keyFile));
        BufferedReader plain = new BufferedReader(new FileReader(plainFile));
        
       // BufferedReader testKey = new BufferedReader(new StringReader("0f1571c947d9e8590cb7add6af7f6798"));
       // BufferedReader testPlain = new BufferedReader(new StringReader("0123456789abcdeffedcba9876543210"));

        PrintWriter writer = new PrintWriter(cipherFile); //, "UTF-8"
        
        // State matrix
        int[][] state = new int[4][4];
        
        // Cipher key matrix
        int[][] cipherKey = new int[4][4];
        
        String line;
        /** Encryption loop until each line from plain is encrypted */
        while((line = plain.readLine()) != null) { // gets line from input file and checks if end of file was reached
        key = new BufferedReader(new FileReader(keyFile)); //refresh key so we dont read in empty values for key (ECB)
        // Get next line from input file
        //String line = plain.readLine();
        BufferedReader lineReader = new BufferedReader(new StringReader(line));
        
        // Fill state matrix using lineReader
        for(int col = 0; col<4; col++)
            for(int row=0; row<4; row++)
            {
                char leftChar=(char)lineReader.read();
                char rightChar=(char)lineReader.read();
                
                // if a character is >255, we have run out of characters and must pad 0s
                if(leftChar>255)
                    state[row][col]=Integer.parseInt("00", 16);
                else if(rightChar>255)
                    state[row][col]=Integer.parseInt(leftChar+"0", 16);
                else
                    state[row][col]=Integer.parseInt((""+leftChar+rightChar), 16);
            }

        // Fill cipherKey matrix using key file
        for(int col = 0; col<4; col++)
            for(int row=0; row<4; row++)
            {
                char leftChar=(char)key.read();
                char rightChar=(char)key.read();
                
                // if a character is >255, we have run out of characters and must pad 0s
                // though in theory, the key shouldn't need any of these checks
                if(leftChar>255)
                    cipherKey[row][col]=Integer.parseInt("00", 16);
                else if(rightChar>255)
                    cipherKey[row][col]=Integer.parseInt(leftChar+"0", 16);
                else
                    cipherKey[row][col]=Integer.parseInt((""+leftChar+rightChar), 16);
            }
        
        /** AES implementation start */
        
        // Initial round: addRoundKey
        addRoundKey(state, cipherKey);
        
        // Encrypt state rounds (loop 9 times)
        for(int round = 1; round<=9; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        scheduleRound(cipherKey, round);
        addRoundKey(state, cipherKey);
        }
        
        // Final round (no mixColumns)
        subBytes(state);
        shiftRows(state);
        scheduleRound(cipherKey, 10);
        addRoundKey(state, cipherKey);
        
        /** AES implementation end */
        
        // Now the block is encrypted. Output block to file and loop back for next line/block
        for(int col = 0; col<state.length; col++)
            for(int row = 0; row<state.length; row++) {
                if(Integer.toHexString(state[row][col]).length()<2) // catch int values equivalent to 0x0f or lower
                    writer.print("0"+Integer.toHexString(state[row][col])); // print hex byte to file
                else
                    writer.print(Integer.toHexString(state[row][col]));
            }
        writer.println(); // move to next line
        
        
        
       // System.out.println(Integer.toString());
        //System.out.println(Integer.parseInt((""+(char)plain.read()+(char)plain.read()), 16));
        //Integer.to
        //System.out.println(Integer.parseInt((""+plain.read()).concat((char)plain.read()), 16));
        //plain.readLine();
        //plain.readLine();
        /*int kek = 0x67;
        char c = (char)-1;
        System.out.println("This is c: "+(char)lineReader.read());
        System.out.println(Arrays.deepToString(state));
        System.out.println(424^283);
        
        System.out.println(160^40);
        System.out.println(Integer.toHexString(kek));
        System.out.println(Integer.toHexString(kek^0xdf));//this (^) is XOR, this works. works same with int values.
        System.out.println(kek);
        System.out.println(Integer.parseInt("67", 16));//parse string as 16 bit hex*/
        
        } // END OF WHILE LOOP
        
        // close them memory leaks
        key.close();
        plain.close();
        writer.close();
    }

    //Substitute each element of state matrix with S-box
    public static void subBytes(int[][] state) {
        for(int col = 0; col<state.length; col++)
            for(int row = 0; row<state.length; row++) {
                String hex = Integer.toHexString(state[row][col]);
                //System.out.println(hex);
                if(hex.length()<2) // hex such as 0a becomes just a, so this catches that
                    state[row][col]=sBox[0][Integer.parseInt(hex.substring(0), 16)];
                else
                    state[row][col]=sBox[Integer.parseInt(hex.substring(0, 1), 16)][Integer.parseInt(hex.substring(1), 16)];
            }  
    }
    
    // Rotation shift array left by 1
    public static void rotate1(int row[]) {
        int temp = row[0];
        
        for(int i=0; i<row.length-1; i++) {
            row[i] = row[i+1];
        }
        row[row.length-1]=temp;
    }
    
    // Shift rows of state matrix
    public static void shiftRows(int[][] state) {
        rotate1(state[1]);
        
        rotate1(state[2]);
        rotate1(state[2]);
        
        rotate1(state[3]);
        rotate1(state[3]);
        rotate1(state[3]);
    }
    
    // Mix columns of state matrix (this is so bootleg)
    public static void mixColumns(int[][] state) {
        //stores mult values
        int[] mult = new int[state.length];
        //stores new state values
        int[] temp = new int[state.length];
            
        for(int k=0; k<state.length; k++) { // for each column of state matrix
            for(int i=0; i<state.length; i++) { //for each element in the column
                    for(int j=0; j<state.length; j++) // multiply elements in matrix
                    {
                        if(mixMatrix[i][j]==0x03)
                            mult[j]=(state[j][k]*0x02)^state[j][k];
                        else
                        mult[j]=state[j][k]*mixMatrix[i][j];
                        //System.out.print(mult[j]+" ");
                        if(mult[j]>255)
                            mult[j]=mult[j]^283; // 283 is decimal representation of Galois irreducible polynomial
                    }
                    // XOR mult values and update temp
                    temp[i]=mult[0]^mult[1]^mult[2]^mult[3];
                    //System.out.print(temp[i]+" ");
            }
        // now that temp is full, update state
        for(int i=0; i<temp.length; i++)
            state[i][k]=temp[i];
        }  
    }
    
    // Add round key to state
    public static void addRoundKey(int[][] state, int[][] roundKey) {
        for(int col = 0; col<state.length; col++)
            for(int row = 0; row<state.length; row++)
                state[row][col] = state[row][col]^roundKey[row][col];
    }
    
    // Key schedule 1 round. Meant for rounds 1-10
    public static void scheduleRound(int[][] roundKey, int round) {
        int[] tempCol = new int[roundKey.length];
        // rotate word; rotWord
        for(int i=0; i<roundKey[0].length-1; i++)
            tempCol[i]=roundKey[i+1][3];
        tempCol[3]=roundKey[0][3];
        
        // Substitute bytes with s-box
        for(int row = 0; row<tempCol.length; row++) {
            String hex = Integer.toHexString(tempCol[row]);
            if(hex.length()<2) // hex such as 0a becomes just a, so this catches that
                tempCol[row]=sBox[0][Integer.parseInt(hex.substring(0), 16)];
            else
                tempCol[row]=sBox[Integer.parseInt(hex.substring(0, 1), 16)][Integer.parseInt(hex.substring(1), 16)];
        }
        
        // XOR first elements of tempCol, roundKey[row][col], Rcon round
        roundKey[0][0]=tempCol[0]^roundKey[0][0]^rCon[round];
        // XOR rest of tempCol and roundKey (Rcon is now 0, so omitted)
        for(int i = 1; i<tempCol.length; i++)
            roundKey[i][0]=tempCol[i]^roundKey[i][0];
        
        // set roundKey[i][1-3]
        for(int col = 1; col<roundKey.length; col++)
            for(int row = 0; row<roundKey.length; row++)
                roundKey[row][col]=roundKey[row][col]^roundKey[row][col-1];
    }
    
    
}
