package com.lc.security.util;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;


public class RSACoder extends Coder{

	public static final String RSA_ALGORITHM = "RSA";
	public static final String SIGNATURE_ALGORITHM = "MD5withRSA";
	
	private static final String PUBLIC_KEY = "RSAPublicKey";
	private static final String PRIVATE_KEY = "RSAPrivateKey";
	
	/**
	 * Sign
	 * @param data
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static String sign(byte[] data, String privateKey) throws Exception{
		//
		byte[] keyBytes = decryptBASE64(privateKey);
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
		PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(priKey);
		signature.update(data);
		return encryptBASE64(signature.sign());
	}
	
	/**
	 * Verify singnature
	 * @param data
	 * @param publicKey
	 * @param sign
	 * @return
	 * @throws Exception
	 */
	public static boolean verify(byte[] data, String publicKey, String sign) throws Exception{
		byte[] keyBytes = decryptBASE64(publicKey);
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
		PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(pubKey);
		signature.update(data);
		return signature.verify(decryptBASE64(sign));
	}
	
	/**
	 * Decryption by privateKey.
	 * @param data
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPrivate(byte[] data, String privateKey) throws Exception{
		byte[] keyBytes = decryptBASE64(privateKey);
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
		Key priKey = keyFactory.generatePrivate(pkcs8KeySpec);
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, priKey);
		
		return cipher.doFinal(data);
	}
	
	/**
	 * Decryption by publicKey.
	 * @param data
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPublic(byte[] data, String publicKey) throws Exception{
		byte[] keyBytes = decryptBASE64(publicKey);
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
		Key pubKey = keyFactory.generatePublic(x509KeySpec);
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, pubKey);
		return cipher.doFinal(data);
	}
	
	/**
	 * Encryption by privateKey.
	 * @param data
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPrivate(byte[] data, String privateKey) throws Exception{
		byte[] keyBytes = decryptBASE64(privateKey);
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
		Key priKey = keyFactory.generatePrivate(pkcs8KeySpec);
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, priKey);
		return cipher.doFinal(data);
	}
	
	/**
	 * Encryption by publicKey.
	 * @param data
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPublic(byte[] data, String publicKey) throws Exception{
		byte[] keyBytes = decryptBASE64(publicKey);
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
		Key pubKey = keyFactory.generatePublic(x509KeySpec);
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		return cipher.doFinal(data);
	}
	
	/**
	 * Get privateKey.
	 * @param keyMap
	 * @return
	 * @throws Exception
	 */
	public static String getPrivateKey(Map<String, Object> keyMap) throws Exception{
		Key privateKey = (Key) keyMap.get(PRIVATE_KEY);
		return encryptBASE64(privateKey.getEncoded());
	}
	
	/**
	 * Get publicKey.
	 * @param keyMap
	 * @return
	 * @throws Exception
	 */
	public static String getPublicKey(Map<String, Object> keyMap) throws Exception{
		Key publicKey = (Key) keyMap.get(PUBLIC_KEY);
		return encryptBASE64(publicKey.getEncoded());
	}
	
	/**
	 * Initialize secret key
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> initKey() throws Exception{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PrivateKey priKey = keyPair.getPrivate();
		PublicKey pubKey = keyPair.getPublic();
		Map<String, Object> keyMap = new HashMap<String, Object>(2);
		keyMap.put(PRIVATE_KEY, priKey);
		keyMap.put(PUBLIC_KEY, pubKey);
		return keyMap;
	}
}
