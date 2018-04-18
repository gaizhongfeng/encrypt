package com.hpe.nfvd.fulfillment.encryption;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
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
	 * @param keyType    
	 * get file type , Can have the following three types:
	 * public.key.path
	 * private.key.path
	 * rsa.key.path
	 * 
	 * @return
	 * file path
	 * 
	 * 
	 * default value£º
	 * The default value is the encrypted file under the resource path
	 * @throws Exception 
	 * 
	 */
	
	public static String   getNFVD_PATCHER_KEY_FILE_Path(String keyType) throws Exception{			
		
		Properties properties = new Properties();  
		try {
			// /etc/opt/OV/ServiceActivator/config/nfvd.properties
			File properties_file = new File("/etc/opt/OV/ServiceActivator/config/nfvd.properties");   		
			 //Read properties file
//			File properties_file = new File("C:\\temporary\\nfvd.properties");
			InputStream stream = new FileInputStream(properties_file);
			
			//load properties file 	
			properties.load(stream); 																				
							}
					 		catch(Exception e){
					 			//return default file 
					 			return  getKeyContext(EncryptionUtils.class.getResource("/"+keyType+".key").getPath() );// EncryptionUtils.class.getResourceAsStream("/"+keyType+".tmp.key.der");
					 	}

		String filePath=properties.getProperty(keyType+".key.path");  								
		
 
		if(filePath==null  ||filePath.equals("")){												
			//if file path not exist, Returns the default value.
			
			return   getKeyContext( EncryptionUtils.class.getResource("/"+keyType+".key").getPath() );//EncryptionUtils.class.getResourceAsStream("/"+keyType+".tmp.key.der");
		}		
		
 		try{
 			return getKeyContext( filePath);
	     
		} catch (Exception e) {
//			 System.out.println("keyFile not exist:"+e);
			//Returns the default value if there is an exception 
			return   getKeyContext( EncryptionUtils.class.getResource("/"+keyType+".key").getPath() ) ;//EncryptionUtils.class.getResourceAsStream("/"+keyType+".tmp.key.der");	
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
