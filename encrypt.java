package NSDL;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import com.ibm.misc.BASE64Decoder;
import com.ibm.misc.BASE64Encoder;

public class ProteanTech {
	static String jkspwd, enpass = "";
	static String base64PrivateKey, base64publickey = null;
	static HashMap<String, String> hashmap_public = new HashMap<>();

    //static String certPath="C:\\Users\\vtcs1953203\\Desktop\\Cerificate\\EIS_ENC_UAT_PUB.cer";
	//static String certPath="C:\\Users\\vtcs1953203\\Desktop\\Cerificate\\NSDL_OVD_Pub.cer";
	//Public Certificate for NPS API
	//static String certPath="C:\\Users\\vtcs1953203\\Desktop\\Cerificate\\NSDL_OVD_Pub.cer";
	//static String certPath_1="C:\\Users\\vtcs1953203\\Desktop\\Cerificate\\NPS_PROTEAN.cer";
	//static String certPath="C:\\Users\\vtcs1953203\\Desktop\\Cerificate\\protean_NPS.cer";
//	 static String propertiesPath =	"C:\\Users\\vtcs1953203\\Desktop\\Cerificate\\KeyMapper.properties";
//     static String jkspath="C:\\Users\\vtcs1953203\\Desktop\\Cerificate\\ibmdevportal.jks"; 

	// static String jkspath =
	// "C:\\Users\\vtcs1953203\\Desktop\\Cerificate\\ibmdevportal.jks";
//////static String dsjkspath="/opt/IBM/SIT_RSA_KeyStore/SitTesting.jks";
	// static String dsjkspath =
	// "C:\\Users\\vtcs1953203\\Desktop\\Cerificate\\ibmdevportal.jks";
	// static String TSjkspath =
	// "C:\\Users\\vtcs1953203\\Desktop\\Cerificate\\ibmdevportal.jks";
//static String certPath = "C:\\Users\\vtcs1953203\\Desktop\\Cerificate\\EIS_ENC_UAT_PUB.cer";
	//static String certPath ="C:\\Users\\vtcs1953203\\Desktop\\NSDL_CERTIFICATE\\capricorn.cer";

	// static String
	// crmPubKey="C:\\Users\\VTCS1824263\\Documents\\vahan_parivahan_gov_in.cer";
	// static String
	// propertiesPath="C:\\Users\\VTCS1824263\\Documents\\KeyMapper.properties";
	// static String jkspath="C:\\Users\\VTCS1824263\\Documents\\ibmdevportal.jks";
//	   static String jkspath="C:\\Users\\VTCS1824263\\Downloads\\vahan_parivahan_gov_in.crt";

	// static String
	// TSjkspath="C:\\Users\\tcs1594712\\Desktop\\Rohit\\Certificates\\ibmdevportal.jks";

   //static String certPath = "/opt/IBM/RSAKeystore/EIS_ENC_UAT_PUB.cer";
   // static String certPath="/opt/IBM/EndPoint_Public/capricorn.cer";
    static String certPath="/opt/IBM/EndPoint_Public/NSDL_OVD_Pub.cer";
    static String certPath_1="/opt/IBM/EndPoint_Public/NPS_PROTEAN.cer";
	static String propertiesPath = "/opt/IBM/PropertyFile/KeyMapper.properties";
	static String jkspath = "/opt/IBM/RSAKeystore/ibmdevportal.jks";

	public static String getAlphaNumericString() {
		int n = 32;
		SecureRandom rnd = new SecureRandom();
		int n1 = 10000000 + rnd.nextInt(9999999);
		String ranNum = String.valueOf(n1);
		String secKey = ranNum + ranNum + ranNum + ranNum;
		StringBuilder sb = new StringBuilder(n);
		sb.append(secKey);
		return sb.toString();
	}

	public static String AESEncrypt_GCM(String message, String key) {
		try {
			byte[] keybyte = key.getBytes("UTF-8");
			byte[] ivkey = Arrays.copyOf(keybyte, 12);
			SecretKeySpec seckey = new SecretKeySpec(keybyte, "AES");
			Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, ivkey);
			c.init(Cipher.ENCRYPT_MODE, seckey, gcmParameterSpec);
			byte[] encvalue = c.doFinal(message.getBytes("UTF-8"));			
			String encryptedvalue = new BASE64Encoder().encode(encvalue).replaceAll("\r\n", "");
			return encryptedvalue;
		} catch (IOException e) {
			return "X-JavaError" + " " + e.toString();
		} catch (NoSuchAlgorithmException e) {
			return "X-JavaError" + " " + e.toString();
		} catch (NoSuchPaddingException e) {
			return "X-JavaError" + " " + e.toString();
		} catch (InvalidKeyException e) {
			return "X-JavaError" + " " + e.toString();
		} catch (InvalidAlgorithmParameterException e) {
			return "X-JavaError" + " " + e.toString();
		} catch (IllegalBlockSizeException e) {
			return "X-JavaError" + " " + e.toString();
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
	}

	public static String AESDecrypt_GCM(String message, String key) {
		if (message.trim().length() == 0) {
			return "X-JavaError" + " " + "request body is empty";
		}
		try {
			byte[] keybyte = key.getBytes("UTF-8");
			byte[] ivkey = Arrays.copyOf(keybyte, 12);
			byte[] encvalue = new BASE64Decoder().decodeBuffer(message);
			SecretKeySpec seckey = new SecretKeySpec(keybyte, "AES");
			Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, ivkey);
			c.init(Cipher.DECRYPT_MODE, seckey, gcmParameterSpec);
			byte[] decvalue = c.doFinal(encvalue);
			String decryptedvalue = new String(decvalue);
			return decryptedvalue;
		} catch (IOException e) {
			return "X-JavaError" + " " + e.toString();
		} catch (NoSuchAlgorithmException e) {
			return "X-JavaError" + " " + e.toString();
		} catch (NoSuchPaddingException e) {
			return "X-JavaError" + " " + e.toString();
		} catch (InvalidKeyException e) {
			return "X-JavaError" + " " + e.toString();
		} catch (InvalidAlgorithmParameterException e) {
			return "X-JavaError" + " " + e.toString();
		} catch (IllegalBlockSizeException e) {
			return "X-JavaError" + " " + e.toString();
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
	}

	public static String RSAEncrypt(String data) {
		String encData = "";
		try {
			/*
			 * if (base64publickey == null) { //String key = base64publickey =
			 * getPublicKey(certPath); String key = base64publickey =
			 * getPublicKey(crmPubKey); if (key.contains("X-JavaError")) { return
			 * "X-JavaError" + " " + key; } }
			 */
			// base64publickey = getPublicKey(certPath);
			base64publickey = getPublicKey(certPath);
			byte[] base64decpublivKey = new BASE64Decoder().decodeBuffer(base64publickey);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(base64decpublivKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey pubKey = keyFactory.generatePublic(keySpec);
			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			byte[] encdatabyte = cipher.doFinal(data.getBytes("UTF-8"));
			encData = new BASE64Encoder().encode(encdatabyte).replaceAll("\r\n", "");
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
		return encData;
	}
	
	public static String RSAEncrypt_1(String data) {
		String encData = "";
		try {
			/*
			 * if (base64publickey == null) { //String key = base64publickey =
			 * getPublicKey(certPath); String key = base64publickey =
			 * getPublicKey(crmPubKey); if (key.contains("X-JavaError")) { return
			 * "X-JavaError" + " " + key; } }
			 */
			// base64publickey = getPublicKey(certPath);
			base64publickey = getPublicKey_1(certPath_1);
			byte[] base64decpublivKey = new BASE64Decoder().decodeBuffer(base64publickey);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(base64decpublivKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey pubKey = keyFactory.generatePublic(keySpec);
			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			byte[] encdatabyte = cipher.doFinal(data.getBytes("UTF-8"));
			encData = new BASE64Encoder().encode(encdatabyte).replaceAll("\r\n", "");
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
		return encData;
	}

	public static String RSADecrypt(String encdata) {
		String data = "";
		try {
			if (base64PrivateKey == null) {
				base64PrivateKey = getPrivateKey();
			}
			// System.setProperty("com.ibm.crypto.provider.DoRSATypeChecking","false");
			byte[] privebase64decKey = new BASE64Decoder().decodeBuffer(base64PrivateKey);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privebase64decKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privaKey = keyFactory.generatePrivate(keySpec);

			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
			cipher.init(Cipher.DECRYPT_MODE, privaKey);
			byte[] dataByte = new BASE64Decoder().decodeBuffer(encdata);
			data = new String(cipher.doFinal(dataByte));
		}

		catch (Exception e) {
			return "X-JavaError" + " " + e.getMessage();
		}
		return data;

	}

	public static String getPublicKey(String certPath) {
		try {
			FileInputStream fin = new FileInputStream(certPath);
			CertificateFactory f = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) f.generateCertificate(fin);
			PublicKey publicKey = certificate.getPublicKey();
			byte[] pk = publicKey.getEncoded();
			base64publickey = DatatypeConverter.printBase64Binary(pk);
			fin.close();
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
		return base64publickey;
	}
	
	public static String getPublicKey_1(String certPath_1) {
		try {
			FileInputStream fin = new FileInputStream(certPath);
			CertificateFactory f = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) f.generateCertificate(fin);
			PublicKey publicKey = certificate.getPublicKey();
			byte[] pk = publicKey.getEncoded();
			base64publickey = DatatypeConverter.printBase64Binary(pk);
			fin.close();
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
		return base64publickey;
	}

	public static String AESEncrypt(String message, String key) {
		try {
			byte[] keybyte = key.getBytes("UTF-8");
			byte[] ivkey = Arrays.copyOf(keybyte, 16);
			IvParameterSpec iv = new IvParameterSpec(ivkey);
			SecretKeySpec seckey = new SecretKeySpec(keybyte, "AES");
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			c.init(Cipher.ENCRYPT_MODE, seckey, iv);
			byte[] encvalue = c.doFinal(message.getBytes("UTF-8"));
			String encryptedvalue = new BASE64Encoder().encode(encvalue).replaceAll("\r\n", "");
			return encryptedvalue;
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
	}

	public static String AESDecrypt(String message, String key) {
		try {
			byte[] keybyte = key.getBytes("UTF-8");
			byte[] ivkey = Arrays.copyOf(keybyte, 16);
			IvParameterSpec iv = new IvParameterSpec(ivkey);
			byte[] encvalue = new BASE64Decoder().decodeBuffer(message);
			SecretKeySpec seckey = new SecretKeySpec(keybyte, "AES");
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			c.init(2, seckey, iv);
			byte[] decvalue = c.doFinal(encvalue);
			String decryptedvalue = new String(decvalue);
			return decryptedvalue;
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
	}

	public static String digitalSignature(String data) {
		String encData = "";
		try {
			/*
			 * if (base64PrivateKey == null) { base64PrivateKey = getPrivateKey(); }
			 */
			base64PrivateKey = getPrivateKey();
			byte[] privebase64decKey = new BASE64Decoder().decodeBuffer(base64PrivateKey);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privebase64decKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			Signature privateSignature = Signature.getInstance("SHA256withRSA");
			PrivateKey privaKey = keyFactory.generatePrivate(keySpec);
			privateSignature.initSign(privaKey);
			privateSignature.update(data.getBytes("UTF-8"));
			byte[] s = privateSignature.sign();
			encData = new BASE64Encoder().encode(s).replaceAll("\r\n", "");
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
		return encData;
	}

	public static String getPrivateKey() {
		try {
			jkspwd = getProperty("aesk", propertiesPath);
			enpass = getProperty("enpass", propertiesPath);
			boolean isAliasWithPrivateKey = false;
			KeyStore keyStore = KeyStore.getInstance("JKS");
			jkspwd = AESDecrypt(enpass, jkspwd);
			if (!jkspwd.contains("X-JavaError")) {
				keyStore.load(new FileInputStream(jkspath), jkspwd.toCharArray());
				Enumeration<String> es = keyStore.aliases();
				String alias = "";
				while (es.hasMoreElements()) {
					alias = (String) es.nextElement();
					if (isAliasWithPrivateKey = keyStore.isKeyEntry(alias)) {
						break;
					}
				}
				if (isAliasWithPrivateKey) {
					KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias,
							new KeyStore.PasswordProtection(jkspwd.toCharArray()));
					PrivateKey myPrivateKey = pkEntry.getPrivateKey();
					byte[] privateKey = (myPrivateKey.getEncoded());
					base64PrivateKey = DatatypeConverter.printBase64Binary(privateKey);
				}
			} else {
				base64PrivateKey = jkspwd + " : Error in Decryption of keystore password";
			}
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
		return base64PrivateKey;
	}

	public static String getProperty(String key, String propertiesPath) {
		BufferedReader reader;
		try {
			reader = new BufferedReader(new FileReader(propertiesPath));
			Properties p = new Properties();
			p.load(reader);
			return p.getProperty(key);
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
	}

	public static String digiSignVerify(String data, String signature) {
		String SigVerify = "";
		try {
			/*
			 * if (base64publickey == null) { String key = base64publickey =
			 * getPublicKey(crmPubKey); if (key.contains("X-JavaError")) { return
			 * "X-JavaError" +" " + key; } }
			 */
			// base64publickey = getPublicKey(certPath);
			base64publickey = getPublicKey(certPath);
			{
				byte[] base64decpublivKey = new BASE64Decoder().decodeBuffer(base64publickey);
				X509EncodedKeySpec keySpec = new X509EncodedKeySpec(base64decpublivKey);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				PublicKey pubKey = keyFactory.generatePublic(keySpec);
				Signature privateSignature = Signature.getInstance("SHA256withRSA");
				privateSignature.initVerify(pubKey);
				privateSignature.update(data.getBytes());
				byte[] y = new BASE64Decoder().decodeBuffer(signature);
				boolean bool = privateSignature.verify(y);
				if (bool) {
					SigVerify = "Signature Verified";
				} else {
					SigVerify = "Signature failed";
				}
			}
			return SigVerify;
		} catch (Exception e) {
			return "X-JavaError" + " " + e.toString();
		}
	}

	public static void main(String[] args) {
		//String key = getAlphaNumericString();
		String key = "11111111111111111111111111111111";
		// System.out.println("Key : "+key);
	    String data ="{\"userId\": \"1300201WS\",\"pran\": \"110182894682\"}"; 
	                  	  
//			"{\r\n" + 
//				"        \"drivinglicencenumber\":\"TS28Q12340854\",\r\n" + 
//			"      \"dob\": \"01/12/2020\",\r\n" + 
//			"        \"rrn\":\"234567\"\r\n" + 			"    }";
		
		String AESkey = RSAEncrypt(key);
		System.out.println("ACCESSTOKEN: " + AESkey);
//		String ENC = AESEncrypt_GCM(data, key);
//		String digi = digitalSignature(data);
		
		
		//System.out.println();
		
	//	System.out.println(digitalSignature("{\"drivinglicencenumber\":\"MH1020180004422\",\"dob\":\"29/07/1999\",\"rrn\":\"SBICB23049749776759789289\"}"));
		
		//System.out.println(digiSignVerify("{\"rrn\":\"SBICB23742994179150141039\",\"age\":\"22\",\"assembly_constituency\":\"Belapur\",\"dist\":\"Thane\",\"epic_number\":\"YTR9103359\",\"name\":\"TUSHAR YUVRAJ POL\\nतुषार युवराज पोळ\",\"parlimentary_constituency\":\"Thane\",\"polling_station\":\"St. Xavier's School, Ground Floor, Room No. 2, Sector 3, Nerul, Navi Mumbai.400706.\",\"relative_name\":\"YUVRAJ POL\\nयुवराज पोळ\",\"state\":\"Maharashtra\"}","xcYEWR6Ho0xB5a5LS5tKIVmM0PyNKm4Rik8uAWuvlWGjH0vcQiez6FZuK/BQNwlbfkpheH+NS1/mIKOobtXa++JDZ4LpPemEOTah071ssZ47G9egimXnIdSBKFL27kCFUk1zZdtvPXsBOBWwyFlTT7U8FWdVY/R24Dn0WMxLOAKh8LGcfEydNJ8oMJlCJxBl9zoq3FXX1YaFX7h1UIYtfTnmzjo01vIJlLsTtpyqpwBKtssqG5apJsvlGsjUq7vuGMA+eiL7yZ/qPAlL6RAXTIvG9GuOHTHGILgNjaB8wBnylNKvW0pvFH13pLUkbXvP5ZsVOWo4TBTrFQYr0HKcOQ=="));
//		System.out.println("REQUEST: "+ ENC);
//		System.out.println("DIGI :"+digi);
		//System.out.println("AESkey : " +AESkey);
	    System.out.println("request: "+ AESEncrypt_GCM(data, key));
		//String decData=AESDecrypt_GCM("DXTx20EjQCRg0roj2IeqSN48SNwfTv+whGTaIGp1VBFo0BYBys5K98gBL+w8AJ2bnqo2TYLH8YZv5mL1X6nsULlmlfwfMbMtqfbSOUWg06b72X/c8OXgPMrzVREesb/+SWi7L+I+8jQ2ZEKo3urYidVbQZrHUNs69HQUKua7tUEoyd3zy3IcLnEKAXNZbmg/bz2/HVhTiQVCYcWi", "11111111111111111111111111111111");
		//String decData="{\"drivinglicencenumber\": \"MH1020180004422\",\"dob\": \"29/07/1999\",\"rrn\": \"SBICB23049749776751580191\"}";
		//System.out.println(decData);
		//String AESKey = RSADecrypt("rcb7kZpohHazm4RwsV06FRi/lmh4ZjXUTkgGzVNowJYS3BCSsGKj5Z/5X2m3kVbaH5Bdelau9W36QQ2icqtGv7m+8lY2dhWFoHgqFH6/qD7r0QCqOa+nhnzctl7mU8oFce2VO+2soCf52ukQfB+ddw5kW7eOBEDQgdblxysTBJSwvJrPZq8ezQYT4WY/0vJRJksAMkjRa0jM1ljRrpGjA8sc4RHtswJjGzphhbyS5yokgftIgL/v2cx2oeRN7w04vQOcUwFGd1Ukic+TSj79dbTImgSZ99+04GYwfpG3MAHo2prh1yKLB2O8kjE4yukUzsbome/l15QunBsRoRHdgw==");
		//System.out.println("AESKeydec: "+ AESKey);
		//System.out.println(AESDecrypt_GCM("DXa11lYmUgh8x7k4yMD+cMBwW9gYR+mwhGTyBi8sElgLjUF/j5ccoIgDYqJ6RIeK2eJfC5LS/NMquzy+K+OpXqE2ovxJYuUHy830HFf+lPipjzzMor+zLYq5A1Fk5qqiCji2kwfTt/F5vjoZThyJsv89Tg==", "11111111111111111111111111111111"));
		 String digiSign = digitalSignature(data);
		 System.out.println("digiSign : "+digiSign);
		// String aesDec =
		 //RSADecrypt("NCTRpfnkV4YaSRBHmbd/KFtXHLq4YIvImYChOrVI0n3Ahhm2D5VGihXqxSMW00qyUDJRN40RyRXZYgn/Y5Duf01y9jLAPYi9vVT++UpqQQycuT0KQOuL3hj8THo+umRGVM5JXhu/GS9SXBuYk+l39OoZWlV62EeZm9z+sGbnjLKe6w5am9mXMALAeSZNLhVmqmYGKhaumR2cEALu5J8fpCUGh+/5FmlUEcZJha70qIzPH8or7L/IxTgbR+4EZ6Rng5wPVRsms5QSxxSYMrsB6nYQFNM9NIdF1frE7Z9ZhY8LnwH0mOacXcsMgoMMZzVMgQ4fzsPGW6BgCI6RVLnXvw==");
		 //System.out.println("AESkey : "+rsaDec);
		// System.out.println("DecKey:
		// "+RSADecrypt("lljrKeX510qtE9dGVRvjXPT2zsA5BHZrty7EqGo/RF1m0Fy2g8jCpb9wC8YNYVIZC0DiZ53m9IdZCHO5/wza7+O6ULU30K1REBwHbdcKPS4w5wYYMOGjS2uB1BGLk6UrpYHlf034aj82dp7Tb0SHxwSXWrL07V805NTmAL7cto+Xiyfl9YDWLbjKtnFpqmDcNfL0sRF76+zRT7obg9LragqxygVSGgYtdZZjcQ1lu0rtvCWwoiIXltVkYxDGQRJe7r2S6jl/tzan8m5PNanwgguI3X3uzYU3kqTurSak3zXMaLOWgwa71waq5pKtwgJ9Ypc+D8RuAW8puvTkQ8LHQg=="));
		//String digiSingData = "cszUEzXrpuZ7BOZDMfDpwIEwxeLahjrHyqVLLXOobXBDy/M+I9NX9O8YEckiwpCo1YUYexI+6yuN973BOOiUzl2rNJeJvwF3OAgz0FOQQT5yTq27VvH703gfkt1UEctgzF3WIFgqr3urLnwryObB4KClGfsgTxFppP1JpukToQKLXmYyxZcmiNU1n7n4jr9pSHnOVJGB04vmVcCnge1vS9JaiMdDZvNLKeTxOz8tMdiOK8KQFJ7vqeDjOAwH52lC5QbLLcKzsoPm+Ewc6aJ5wcXO8hD+lWO4jQvj0A9sz99zq8BN1U2erv2WfVDDydpqDmzpHAcuwLqneHeHpShPVQ==";
		//System.out.println(digiSignVerify(decData,digiSingData));
		// String rsaDec =
		// AESDecrypt_GCM("fAkgp28LZMMjAcvcWDwiFg9cAvzQYTkFn5DyeU+BGdfqCEjL/liWpmTuGgits4OAnWxNAnaFowBUxx8CCg86eDXqs4TET0RpUUwgqtToaIUwO+YtFxajudLB3f5XdG1zsmNVmEGsb8BlB5fGohVuQiPA4j1K/OuWThK7TbiaBHJteIlls0GWRmn/j85HHP/DQRapoTP34MV9gIqnG0p8tDBat9ZrkCC991NTGO96r6OcqNdB","11111111111111111111111111111111");
		// System.out.println("DecData "+rsaDec);
		//System.out.println(AESDecrypt_GCM("kIPDm2K9vqwNbEVSgJuvlBqQLeSKxYDMy+dVxB55EETtENag9an8DZoGTCZmfKGFOFevsHG+9zHBbSPJf/OTmx0L+hvRGc3r1xAyWnL1WQfJprSTmDkVKhHjBC5zjUpg9skrL2/rS74P", key));

	}
}

