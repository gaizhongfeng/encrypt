package com.hpe.nfvd.fulfillment;

import org.junit.Test;

import com.hpe.nfvd.fulfillment.encryption.EncryptionUtils;

import junit.framework.TestCase;

public class EncryptionTest extends TestCase {

//	@Test
//	public void testEncryption() throws Exception {
//		String encriptedText = EncryptionUtils.encrypt("test_string");
//		String decriptedText = EncryptionUtils.decrypt(encriptedText);
//		assertEquals("test_string", decriptedText);
//	}
	
	public static void main(String[] args) throws Exception {
		
		
		String encriptedText = EncryptionUtils.encrypt("test_string");
		 System.out.println(encriptedText);
		String decriptedText = EncryptionUtils.decrypt(encriptedText);

		 System.out.println(decriptedText);
	}

}
