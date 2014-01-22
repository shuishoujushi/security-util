如基本的单向加密算法： 
	BASE64 严格地说，属于编码格式，而非加密算法
	MD5(Message Digest algorithm 5，信息摘要算法)
	SHA(Secure Hash Algorithm，安全散列算法)
	HMAC(Hash Message Authentication Code，散列消息鉴别码)

复杂的对称加密（DES、PBE）、非对称加密算法： 
	DES(Data Encryption Standard，数据加密算法)
	PBE(Password-based encryption，基于密码验证)
	RSA(算法的名字以发明者的名字命名：Ron Rivest, AdiShamir 和Leonard Adleman)
	DH(Diffie-Hellman算法，密钥一致协议)
	DSA(Digital Signature Algorithm，数字签名)
	ECC(Elliptic Curves Cryptography，椭圆曲线密码编码学)
	

BASE64 
按照RFC2045的定义，Base64被定义为：Base64内容传送编码被设计用来把任意序列的8位字节描述为一种不易被人直接识别的形式。（The Base64 Content-Transfer-Encoding is designed to represent arbitrary sequences of octets in a form that need not be humanly readable.） 
常见于邮件、http加密，截取http信息，你就会发现登录操作的用户名、密码字段通过BASE64加密的。 
主要就是BASE64Encoder、BASE64Decoder两个类，我们只需要知道使用对应的方法即可。另，BASE加密后产生的字节位数是8的倍数，如果不够位数以=符号填充。 


MD5 
MD5 -- message-digest algorithm 5 （信息-摘要算法）缩写，广泛用于加密和解密技术，常用于文件校验。校验？不管文件多大，经过MD5后都能生成唯一的MD5值。好比现在的ISO校验，都是MD5校验。怎么用？当然是把ISO经过MD5后产生MD5的值。一般下载linux-ISO的朋友都见过下载链接旁边放着MD5的串。就是用来验证文件是否一致的。 
通常我们不直接使用上述MD5加密。通常将MD5产生的字节数组交给BASE64再加密一把，得到相应的字符串。 


SHA 
SHA(Secure Hash Algorithm，安全散列算法），数字签名等密码学应用中重要的工具，被广泛地应用于电子商务等信息安全领域。虽然，SHA与MD5通过碰撞法都被破解了， 但是SHA仍然是公认的安全加密算法，较之MD5更为安全。

HMAC 
HMAC(Hash Message Authentication Code，散列消息鉴别码，基于密钥的Hash算法的认证协议。消息鉴别码实现鉴别的原理是，用公开函数和密钥产生一个固定长度的值作为认证标识，用这个标识鉴别消息的完整性。使用一个密钥生成一个固定大小的小数据块，即MAC，并将其加入到消息中，然后传输。接收方利用与发送方共享的密钥进行鉴别认证等。 
	