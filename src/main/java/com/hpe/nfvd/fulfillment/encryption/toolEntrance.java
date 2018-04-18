package com.hpe.nfvd.fulfillment.encryption;
import com.hpe.nfvd.fulfillment.encryption.*;
public class toolEntrance {

	public static void main(String[] args) throws Exception {
		
		 
  
		String operation = args[0];   //operation type
		String str = args[1];   //password
		
		if("encrypt".equals(operation)){
			System.out.println( EncryptionUtils.encrypt(str));//
		}
		else{
			if("decrypt".equals(operation)){
			System.out.println(EncryptionUtils.decrypt(str));
			}
			else{
				System.out.println("operation type error!!");
			}
		}
		
	}

}
