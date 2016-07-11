/*
 * Copyright 2014 EMBL-EBI.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package uk.ac.embl.ebi.ega.reencryptionservice.utils;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;

/**
 *
 * @author asenf
 */
public class MyGPGInputStream extends InputStream {
    private final InputStream in;
    private final PGPPublicKey pgKey;
    private int pos;
    
    private final String dest = "/stream"; // Dummy Filename for GPG Instatiation
    
    private ByteArrayOutputStream baos = new ByteArrayOutputStream(); // Local Byte Buffer
    private MessageDigest crypt_digest = null;                                   // PGP
    private OutputStream literalOut = null, encOut = null, compressedOut = null; // PGP
    private int DEFAULT_BUFFER_SIZE = 65 * 1024;                                 // PGP
    private PGPEncryptedDataGenerator encryptedDataGenerator = null;             // PGP
    private PGPCompressedDataGenerator compressedDataGenerator = null;           // PGP
    private PGPLiteralDataGenerator literalDataGenerator = null;                 // PGP
    
    private byte[] encryptedDataBuffer; // Cache encrypted data ready to be read
    
    private boolean closed;
    
    private long readTot, readOut;
    
    public MyGPGInputStream(InputStream in, PGPPublicKey gpgKey) throws IOException {
        this.in = in;
        this.pgKey = gpgKey;
        this.pos = 0;
        
        // Set up the GPG Cipher
        Security.addProvider(new BouncyCastleProvider());        
        try {
            crypt_digest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyGPGInputStream.class.getName()).log(Level.SEVERE, null, ex);
            System.out.println("MD5 Algorithm not installed with Java. Contact Systems.");
            System.out.print(ex.getLocalizedMessage());
        }

        // Encrypted Data Generator -- needs unlimited Security Policy
        encryptedDataGenerator = new PGPEncryptedDataGenerator(
                                PGPEncryptedData.CAST5, true, new SecureRandom(), "BC");
        try {
            encryptedDataGenerator.addMethod(pgKey);
            encOut = encryptedDataGenerator.open(baos, new byte[DEFAULT_BUFFER_SIZE]);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(MyGPGInputStream.class.getName()).log(Level.SEVERE, null, ex);
            System.out.println("No Such Service Provider Error: " + ex.getLocalizedMessage());
        } catch (PGPException ex) {
            Logger.getLogger(MyGPGInputStream.class.getName()).log(Level.SEVERE, null, ex);
            System.out.println("PGP Error: " + ex.getLocalizedMessage());
            System.out.println("Ensure that Unlimited Strength Policy files are installed for this JRE:");
            Process java = Runtime.getRuntime().exec("cmd /C java -version");
            BufferedReader in_ = new BufferedReader(new InputStreamReader(java.getInputStream()));
            String line;
            while ((line = in_.readLine()) != null) {
                System.out.print(line);
            }
        }

        // Compression
        compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
        compressedOut = compressedOut = new BufferedOutputStream(compressedDataGenerator.open(encOut));

        // Literal Data Generator and Output Stream
        literalDataGenerator = new PGPLiteralDataGenerator();
        String fileName = this.dest.substring(this.dest.lastIndexOf("/")+1);
        literalOut = literalDataGenerator.open(compressedOut,
                                PGPLiteralData.BINARY, fileName,
                                new Date(),new byte[DEFAULT_BUFFER_SIZE]); // 1<<16

        // Initially fill Stream Cache (baos) with some data
        closed = false; // marks a stream that has reached the end - no more new data coming
        this.readTot = 0;
        this.readOut = 0;
        fillBuffer();
    }

    // Read from this stream -> read from the cache, and refill, if necessary
    @Override
    public int read() throws IOException {
        int r = -1;
        
        if (encryptedDataBuffer!=null && pos>=encryptedDataBuffer.length && !closed)
            fillBuffer();
        
        if (encryptedDataBuffer!=null && pos<encryptedDataBuffer.length)
            r = (int)encryptedDataBuffer[pos++]; // next element in the buffer
        return r;
    }
    
    
    @Override
    public int read(byte b[]) throws IOException {
        return read(b, 0, b.length);
    }

    @Override
    public int read(byte b[], int off, int len) throws IOException {
    
        if (b == null) {
            throw new NullPointerException();
        } else if (off < 0 || len < 0 || len > b.length - off) {
            throw new IndexOutOfBoundsException();
        } else if (len == 0) {
            return 0;
        }

        if (encryptedDataBuffer!=null && pos>=encryptedDataBuffer.length && !closed)
            fillBuffer();
        
        if (pos==encryptedDataBuffer.length && closed) // Indicate Stream end!
            return -1;

        // Set copy pointers
        int toCopy = len, toCopyPos = off, copied = 0;
        
        while (toCopyPos < (off+len)) { // Attempt to fill buffer!
        
            if (encryptedDataBuffer.length-pos < toCopy)
                toCopy = encryptedDataBuffer.length-pos;

            // Copy buffer to b
            System.arraycopy(encryptedDataBuffer, pos, b, toCopyPos, toCopy);
            pos += toCopy; // position in encryptedDataBuffer
            toCopyPos+=toCopy; // position in b
            copied += toCopy; // total number of bytes copied
            toCopy = len-copied; // remaining data to be copied

            // Re-Fill buffer, if necessary or possible
            if (encryptedDataBuffer!=null && pos>=encryptedDataBuffer.length && !closed)
                fillBuffer();
            else if (encryptedDataBuffer!=null && pos>=encryptedDataBuffer.length && closed) // if there is no more data to be read
                break;
        }
        
        return copied;
    }

    @Override
    public long skip(long n) throws IOException {
        long toSkip = n, skipped = 0;
        
        while (skipped < n) {
            
            if (toSkip > (encryptedDataBuffer.length-pos))
                toSkip = encryptedDataBuffer.length-pos;

            pos += toSkip;
            skipped += toSkip;

            if (encryptedDataBuffer!=null && pos>=encryptedDataBuffer.length && !closed)
                fillBuffer();
            else if (encryptedDataBuffer!=null && pos>=encryptedDataBuffer.length && closed) // if there is no more data to be read
                break;
        
        }
        
        return skipped;
    }

    @Override
    public int available() throws IOException {
        
        if (encryptedDataBuffer!=null && pos>=encryptedDataBuffer.length && !closed)
            fillBuffer();
        
        int available = encryptedDataBuffer.length-pos;
        if (available==0 && closed)
            available = -1;
                
        return available;
    }

    @Override
    public void close() throws IOException {
        literalOut.flush();
        literalOut.flush();
        literalOut.close();
        literalDataGenerator.close();
        compressedOut.close();
        compressedDataGenerator.close();
        encOut.close();
        encryptedDataGenerator.close();
        in.close();
        closed = true;
    }

    @Override
    public synchronized void reset() throws IOException {
        throw new IOException("mark/reset not supported");
    }

    @Override
    public boolean markSupported() {
        return false;
    }

    // Helper Function ---------------------------------------------------------
    private void fillBuffer_() {
        try {
            byte[] dataBuffer = new byte[32*1024]; // Read file
            int read = in.read(dataBuffer); // 32K at a time
            this.readTot += read;
            if (read != -1) { // read actual file data
                literalOut.write(dataBuffer, 0, read);        
                literalOut.flush();
            } else { // produce end-of-file data, close teh streams
                literalOut.flush();
                literalOut.flush();
                literalOut.close();
                literalDataGenerator.close();
                compressedOut.close();
                compressedDataGenerator.close();
                encOut.close();
                encryptedDataGenerator.close();
                
                closed = true;
            }
            
            byte[] buf = baos.toByteArray();
            encryptedDataBuffer = new byte[buf.length];
            System.arraycopy(buf, 0, encryptedDataBuffer, 0, buf.length);
            pos = 0;
            baos.reset();
        } catch (IOException ex) {
            System.out.println("Error " + ex.toString());
            Logger.getLogger(MyGPGInputStream.class.getName()).log(Level.SEVERE, null, ex);
        }
    }


    private void fillBuffer() {
        System.out.println("Start: pos = " + pos );
        
        try {
            
            int producedbytes = 0;
            byte[] buf = null;
            
            while (producedbytes == 0 && !closed) { // Loop until there are encrypted bytes in the buffer
                byte[] dataBuffer = new byte[32*1024]; // Read file
                int read = in.read(dataBuffer); // 32K at a time
                this.readTot += read;
                
                if (read != -1) { // read actual file data
                    literalOut.write(dataBuffer, 0, read);        
                    literalOut.flush();
                } else { // produce end-of-file data, close teh streams
                    literalOut.flush();
                    literalOut.flush();
                    literalOut.close();
                    literalDataGenerator.close();
                    compressedOut.close();
                    compressedDataGenerator.close();
                    encOut.close();
                    encryptedDataGenerator.close();

                    closed = true;
                }

                buf = baos.toByteArray();
                producedbytes = buf.length;
            }
            
            //byte[] buf = baos.toByteArray();
            encryptedDataBuffer = new byte[buf.length];
            System.arraycopy(buf, 0, encryptedDataBuffer, 0, buf.length);
            pos = 0;
            baos.reset();
        } catch (IOException ex) {
            System.out.println("Error " + ex.toString());
            Logger.getLogger(MyGPGInputStream.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
}
