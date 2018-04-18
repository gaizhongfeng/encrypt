package com.hpe.nfvd.fulfillment.encryption;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;

import com.hpe.nfvd.fulfillment.exceptions.EncryptionException;

/**
 * @author josealva
 *
 *         To encrypt something via commandline: echo -n "xxxx" | openssl rsautl
 *         -encrypt -inkey nfvd-patcher.pub -pubin -keyform der | xxd -p | tr -d
 *         "\n"
 */
public class EncryptionUtils {

	private static final String RSA_ENCRYPTION = "RSA";


/**
 * decrypt 
 * @param data
 * @return
 * @throws EncryptionException
 * @throws Exception
 */
	public static String decrypt(String data) throws EncryptionException, Exception {
					RSAPrivateKey privateKey = getPrivateKey();
		            Cipher cipher = Cipher.getInstance(RSA_ENCRYPTION);
		            cipher.init(Cipher.DECRYPT_MODE, privateKey);
		            return new String(fileUtils.rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, Base64.decodeBase64(data), privateKey.getModulus().bitLength()), "UTF-8");
		        
		   
	}

	
	/**
	 * encrypt 
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String encrypt(String data) throws Exception  {
		
		RSAPublicKey publicKey = getPublicKey();
		
		Cipher cipher = Cipher.getInstance(RSA_ENCRYPTION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.encodeBase64URLSafeString(fileUtils.rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE, data.getBytes("UTF-8"), publicKey.getModulus().bitLength()));
		
	}
	
 
	private static RSAPrivateKey getPrivateKey() throws  Exception {
	
			String result =  fileUtils.getNFVD_PATCHER_KEY_FILE_Path("private");
		 	KeyFactory keyFactory = KeyFactory.getInstance(RSA_ENCRYPTION);
	        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(result));
	        RSAPrivateKey key = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
	        return key;
	}

	private static RSAPublicKey  getPublicKey() throws  Exception {
	
		
		String result =  fileUtils.getNFVD_PATCHER_KEY_FILE_Path("public");
		  KeyFactory keyFactory = KeyFactory.getInstance(RSA_ENCRYPTION);
	      X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(result.toString()));
	      RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
	      return key;
		
		
	}

	
	
	
	
	
	
	
	
	
	

}