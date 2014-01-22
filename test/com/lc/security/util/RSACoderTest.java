package com.lc.security.util;

import java.util.Map;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;

import com.lc.security.util.RSACoder;

public class RSACoderTest {
	
	private String publicKey;
	private String privateKey;
	
	@Before
	public void setUp() throws Exception{
		Map<String, Object> keyMap = RSACoder.initKey();
		publicKey = RSACoder.getPublicKey(keyMap);
		privateKey = RSACoder.getPrivateKey(keyMap);
		System.err.println("publicKey ---------> " + publicKey);
		System.err.println("privateKey --------> " + privateKey);
	}
	
	@Test
	public void test() throws Exception{
		String input = "abc";
		byte[] bytes1 = RSACoder.encryptByPrivate(input.getBytes(), privateKey);
		byte[] result1 = RSACoder.decryptByPublic(bytes1, publicKey);
		
		Assert.assertEquals(input, new String(result1));
		
		byte[] bytes2 = RSACoder.encryptByPublic(input.getBytes(), publicKey);
		byte[] result2 = RSACoder.decryptByPrivate(bytes2, privateKey);
		
		Assert.assertEquals(input, new String(result2));
	}
	
	@Test
	public void testSign() throws Exception{
		String input = "sign";
		byte[] encryptData = RSACoder.encryptByPrivate(input.getBytes(), privateKey);
		byte[] decryptData = RSACoder.decryptByPublic(encryptData, publicKey);
		
		Assert.assertEquals(input, new String(decryptData));
		
		String signedData = RSACoder.sign(encryptData, privateKey);
		boolean status = RSACoder.verify(encryptData, publicKey, signedData);
		Assert.assertEquals(true, status);
	}
}
