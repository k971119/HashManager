package HashManager;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class PasswordHash {
	
	private final String algorithmType;
	
	public PasswordHash(Algorithm algorithm) {
		switch (algorithm) {
		case SHA256:
			algorithmType = "SHA-256";
			break;
		case SHA512:
			algorithmType = "SHA-512";
			break;
		case MD5:
			algorithmType = "MD5";
			break;
		default:
			algorithmType = "SHA-256";
			break;
		}
	}
	
	
	/**
	 * � 비밀번호 생성
	 * @param word
	 * @return [0] : salt / [1] : hash
	 * @throws NoSuchAlgorithmException
	 */
	public String[] hashing(String word) throws NoSuchAlgorithmException {
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");		//salt 난수
		byte[] bytes = new byte[16];
		random.nextBytes(bytes);
		String salt = new String(Base64.getEncoder().encode(bytes));
		
		String[] password = {salt, makeHash(word, salt)};
		
		return password;
	}
	
	/**
	 * �  해시값 대조
	 * @param word
	 * @param salt
	 * @return true:대조값 일치 / false:대조값 불일치
	 * @throws NoSuchAlgorithmException
	 */
	public boolean CompareHash(String text, String salt, String hash) throws NoSuchAlgorithmException {
		
		if(makeHash(text, salt).equals(hash)) {
			return true;
		}else {
			return false;
		}
	}
	
	private String makeHash(String text, String salt) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(algorithmType);
		md.update(salt.getBytes());
		md.update(text.getBytes());
		
		return String.format("%064x", new BigInteger(1,md.digest()));
	}
}

