package com.hpe.nfvd.fulfillment.encryption;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.rmi.server.ExportException;
import java.util.Properties;

import javax.crypto.Cipher;

import org.apache.commons.io.IOUtils;
/**
 * 
 * @author gaizh
 *
 */ 
public class fileUtils {
	/**
	 * 
	 *
	 * get file type , Can have the following three types:
	 * public.key.path
	 * private.key.path
	 * rsa.key.path
	 * 
	 * @return
	 * file path
	 * 
	 * 
	 * default value��
	 * The default value is the encrypted file under the resource path
	 * @throws Exception 
	 * 
	 */

	///etc/opt/OV/ServiceActivator/config/nfvd.properties
			//"C:\\temporary\\nfvd.properties"
	private static String  FILE_PATH="/etc/opt/OV/ServiceActivator/config/nfvd.properties";

	public static boolean isCustomerKey(){
		Properties properties = new Properties();
		File properties_file = new File(FILE_PATH);
		try {
			InputStream stream = new FileInputStream(properties_file);
			properties.load(stream);
			String pubKey=properties.getProperty("public.key.path");
			String priKey=properties.getProperty("private.key.path");
			String fileType = properties.getProperty("rsa.key.path");
			if(pubKey.equals("") || pubKey==null || priKey.equals("") || priKey ==null || fileType.equals("") || fileType==null){
				return  false;
			}
		}
		catch (Exception e){
			 return  false;
		}
		return true;
	}


	public static String  getKeyType() throws Exception {
		Properties properties = new Properties();
		File properties_file = new File(FILE_PATH);

			InputStream stream = new FileInputStream(properties_file);
			properties.load(stream);

			return  properties.getProperty("rsa.key.path");
	}

	public static String   getNFVD_PATCHER_KEY_FILE_Path(String keyType) throws Exception{			
		
		Properties properties = new Properties();  
		try {

			File properties_file = new File(FILE_PATH);
			InputStream stream = new FileInputStream(properties_file);
			
			//load properties file 	
			properties.load(stream); 																				
							}
					 		catch(Exception e){

					 			InputStream  s = EncryptionUtils.class.getResourceAsStream("/"+keyType+".key") ;
					 			return getKeyContext (s);
					 		}

		String filePath=properties.getProperty(keyType+".key.path");  								
		
// 			System.out.println("filePath:"+filePath);
		if(filePath==null  ||filePath.equals("")){												
			//if file path not exist, Returns the default value.
			
			return   getKeyContext( EncryptionUtils.class.getResource("/"+keyType+".key").getPath() );//EncryptionUtils.class.getResourceAsStream("/"+keyType+".tmp.key.der");
		}		
		
 		try{
 			return getKeyContext( filePath);
	     
		} catch (Exception e) {
			InputStream  s = EncryptionUtils.class.getResourceAsStream("/"+keyType+".key") ;
			return getKeyContext (s);
		
		}   
	
	}



	public static InputStream  getDerNFVD_PATCHER_KEY_FILE_Path(String keyType){

		Properties properties = new Properties();  // create new File parse object
		try {

			File properties_file = new File(FILE_PATH);   		 //Read properties file										//Get file stream based on file path
			InputStream stream = new FileInputStream(properties_file);

			properties.load(stream); 																	//load properties file
		}
		catch(Exception e){
			//System.out.println("load error");
			return   EncryptionUtils.class.getResourceAsStream("/"+keyType+".tmp.key.der");
		}
		String filePath=properties.getProperty(keyType+".key.path");  								//get NFVD_PATCHER_PUBLIC_KEY_FILE  path
		if(filePath==null  ||filePath.equals("")){												//if file path not exist, /Returns the default value
			return   EncryptionUtils.class.getResourceAsStream("/"+keyType+".tmp.key.der");
		}
		//System.out.println("-"+filePath+"*");

		try{

			File key_file = new File(filePath);   												//Get file stream based on file path
			InputStream fileStream = new FileInputStream(key_file);
			return fileStream;
			//return file stream
		} catch (Exception e) {
			//System.out.println("keyFile not exist！");

			return   null;//EncryptionUtils.class.getResourceAsStream("/"+keyType+".tmp.key.der");	//Returns the default value if there is an exception.
		}

	}
	/**
	 * read key file
	 * @param filePath
	 * @return
	 * @throws Exception
	 */
	private static String getKeyContext(String filePath) throws Exception{
		
		  boolean isEnd=false;
		 File key_file = new File(filePath);
	 
	     StringBuilder result = new StringBuilder();
		 BufferedReader br = new BufferedReader(new FileReader(key_file));
        String s = null;
        /**
         * beacuse key file start with "-----BEGIN" end with "-----END "  , so this get context code  
         */
        
        while((s = br.readLine())!=null){

        	if((s.indexOf("-----")>=0) && isEnd){
        		break;
        	}
        	if(s.indexOf("-----")>=0){
        		isEnd=true;
        		continue;
        	}
        	
        	result.append(s);
        }
        br.close();   

	     return result.toString();	
	}

	
	
	private static String getKeyContext(InputStream  in ) throws Exception{
		
		  boolean isEnd=false;
		 
	 
	     StringBuilder result = new StringBuilder();
		 BufferedReader br = new BufferedReader(new InputStreamReader(in));
      String s = null;
      /**
       * beacuse key file start with "-----BEGIN" end with "-----END "  , so this get context code  
       */
      
      while((s = br.readLine())!=null){

      	if((s.indexOf("-----")>=0) && isEnd){
      		break;
      	}
      	if(s.indexOf("-----")>=0){
      		isEnd=true;
      		continue;
      	}
      	
      	result.append(s);
      }
      br.close();   

	     return result.toString();	
	}


	
	
	
	
	  public static byte[] rsaSplitCodec(Cipher cipher, int opmode, byte[] datas, int keySize){
	        int maxBlock = 0;
	        if(opmode == Cipher.DECRYPT_MODE){
	            maxBlock = keySize / 8;
	        }else{
	            maxBlock = keySize / 8 - 11;
	        }

	        ByteArrayOutputStream out = new ByteArrayOutputStream();
	        int offSet = 0;
	        byte[] buff;
	        int i = 0;
	        try{
	            while(datas.length > offSet){
	                if(datas.length-offSet > maxBlock){
	                    buff = cipher.doFinal(datas, offSet, maxBlock);
	                }else{
						buff = cipher.doFinal(datas, offSet, datas.length-offSet);
					}
	                out.write(buff, 0, buff.length);
	                i++;
	                offSet = i * maxBlock;
	            }
	        }catch(Exception e){
	            throw new RuntimeException("execute ["+maxBlock+"] error ", e);
	        }
	        byte[] resultDatas = out.toByteArray();
	        IOUtils.closeQuietly(out);

	        return resultDatas;

	    }
	
	
	
}
