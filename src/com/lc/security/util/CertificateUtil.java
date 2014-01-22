package com.lc.security.util;

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import javax.crypto.Cipher;

import sun.misc.BASE64Encoder;


public class CertificateUtil {

	public static final String X509_TYPE = "X.509";
	
	/**
	 * Get the publickey from given cert file, the certPath stands for cert file, should under src source folder.
	 * @param certPath
	 * @return
	 * @throws Exception
	 */
	public static PublicKey getPublicKeyByCert(String certPath) throws Exception{
		CertificateFactory certFactory = CertificateFactory.getInstance(X509_TYPE);
		Thread.currentThread().getContextClassLoader();
		Certificate certificate = certFactory.generateCertificate(ClassLoader.getSystemResourceAsStream(certPath));
		return certificate.getPublicKey();
	}
	
	/**
	 * According publickey algorithm to do encode for data.
	 * @param data
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	public static String encryptByPublicKey(byte[] data, PublicKey publicKey) throws Exception {
		Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encryptedData = cipher.doFinal(data);
		return new BASE64Encoder().encode(encryptedData);
	}
	
}
