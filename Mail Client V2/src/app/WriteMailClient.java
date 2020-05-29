package app;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.utils.JavaUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.api.services.gmail.Gmail;
import model.keystore.KeyStoreReader;
import model.mailclient.MailBody;
import util.Base64;
import util.GzipUtil;
import util.IVHelper;
import support.MailHelper;
import support.MailWritter;

public class WriteMailClient extends MailClient {

	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	private static final String KEY_STORE_FILE="./data/usera.jks";
	private static final String KEY_STORE_FILE1="./data/userb.jks";
	private static final String KEY_STORE_PASSA= "usera";
	private static final String KEY_STORE_ALIASA = "usera";
	private static final String KEY_STORE_PASS_FOR_PRIVATE_KEYA = "usera";
	private static final String KEY_STORE_ALIASB= "userb";
	private static final String KEY_STORE_PASS_FOR_PRIVATE_KEYB = "userb";
	private static KeyStoreReader keyStoreReader= new KeyStoreReader();
	public static void main(String[] args) {
		
        try {
        	Gmail service = getGmailService();
            
        	System.out.println("Insert a reciever:");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String reciever = reader.readLine();
        	
            System.out.println("Insert a subject:");
            String subject = reader.readLine();
            
            
            System.out.println("Insert body:");
            String body = reader.readLine();
            
            
            //Compression
            String compressedSubject = Base64.encodeToString(GzipUtil.compress(subject));
            String compressedBody = Base64.encodeToString(GzipUtil.compress(body));
            
            //Key generation
            KeyGenerator keyGen = KeyGenerator.getInstance("AES"); 
			SecretKey secretKey = keyGen.generateKey();
			Cipher aesCipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec1 = IVHelper.createIV();
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec1);
			
			
			//sifrovanje
			byte[] ciphertext = aesCipherEnc.doFinal(compressedBody.getBytes());
			String ciphertextStr = Base64.encodeToString(ciphertext);
			System.out.println("Kriptovan tekst: " + ciphertextStr);
			
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec2 = IVHelper.createIV();
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec2);
			
			byte[] ciphersubject = aesCipherEnc.doFinal(compressedSubject.getBytes());
			String ciphersubjectStr = Base64.encodeToString(ciphersubject);
			System.out.println("Kriptovan subject: " + ciphersubjectStr);
			
			//prosledjivanje fajla i lozinke za pristup
    		KeyStore keyStore=keyStoreReader.readKeyStore(KEY_STORE_FILE,KEY_STORE_PASSA.toCharArray());
    		//preuzimanje sertifikata za korisnikab i njegovog javnog kljuca
    		Certificate certificateB=keyStoreReader.getCertificateFromKeyStore(keyStore, KEY_STORE_ALIASB);
    		System.out.println("\n Citanje sertifikata:\n"+certificateB);
    		PublicKey publicKeyB=keyStoreReader.getPublicKeyFromCertificate(certificateB);
    		System.out.println("\n Javni kljuc:\n"+ publicKeyB);
    		//enkripcija session kljuca javnim kljucem korisnika b
    		Security.addProvider(new BouncyCastleProvider());
    		Cipher rsaCipherEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
    		//postavljamo da se enkriptuje tajnim kljucem
    		rsaCipherEnc.init(Cipher.ENCRYPT_MODE, publicKeyB);
    		//kriptovanje
    		byte[] encodedSecretKey = rsaCipherEnc.doFinal(secretKey.getEncoded());
    		System.out.println("Kriptovan secret key: " + Base64.encodeToString(encodedSecretKey));
			
    		
			
			//snimaju se bajtovi kljuca i IV.
			JavaUtils.writeBytesToFilename(KEY_FILE, secretKey.getEncoded());
			JavaUtils.writeBytesToFilename(IV1_FILE, ivParameterSpec1.getIV());
			JavaUtils.writeBytesToFilename(IV2_FILE, ivParameterSpec2.getIV());
			
			//presnosenje enkriptovanog tajnog kljuca u okviru tela bodija
    		MailBody mailBody= new MailBody(ciphertext,ivParameterSpec1.getIV(),ivParameterSpec2.getIV(),encodedSecretKey);
    		String csv=mailBody.toCSV();
    		
    		System.out.println(">>>"+ciphertextStr+" "+csv);
			
        	MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphersubjectStr, ciphertextStr+" "+csv);
        	MailWritter.sendMessage(service, "me", mimeMessage);
        	
        	
    		
    		
    		
    	
        	
        }catch (Exception e) {
        	e.printStackTrace();
		}
	}
}
