package in.bitanxen.poc.util;

import com.google.common.base.Strings;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Log4j2
public class CommonUtil {

    public static String generateAlphaNumeric(int length) {
        char[] ch = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
                'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
                'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
                'z' };

        char[] c = new char[length];
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < length; i++) {
            c[i] = ch[random.nextInt(ch.length)];
        }
        return new String(c);
    }

    public static Map<String, JWK> getJWKPublicKeys(Map<String, JWK> keys) {
        Map<String, JWK> pubKeys = new HashMap<>();

        // pull out all public keys
        for (String keyId : keys.keySet()) {
            JWK key = keys.get(keyId);
            JWK pub = key.toPublicJWK();
            if (pub != null) {
                pubKeys.put(keyId, pub);
            }
        }
        return pubKeys;
    }

    public static Base64URL getCodeHash(JWSAlgorithm signingAlg, String code) {
        return getHash(signingAlg, code.getBytes());
    }

    public static Base64URL getAccessTokenHash(JWSAlgorithm signingAlg, JWT jwt) {
        byte[] tokenBytes = jwt.serialize().getBytes();
        return getHash(signingAlg, tokenBytes);
    }

    public static Base64URL getHash(JWSAlgorithm signingAlg, byte[] bytes) {

        //Switch based on the given signing algorithm - use SHA-xxx with the same 'xxx' bitnumber
        //as the JWSAlgorithm to hash the token.
        String hashAlg = null;

        if (signingAlg.equals(JWSAlgorithm.HS256) || signingAlg.equals(JWSAlgorithm.ES256) || signingAlg.equals(JWSAlgorithm.RS256) || signingAlg.equals(JWSAlgorithm.PS256)) {
            hashAlg = "SHA-256";
        }

        else if (signingAlg.equals(JWSAlgorithm.ES384) || signingAlg.equals(JWSAlgorithm.HS384) || signingAlg.equals(JWSAlgorithm.RS384) || signingAlg.equals(JWSAlgorithm.PS384)) {
            hashAlg = "SHA-384";
        }

        else if (signingAlg.equals(JWSAlgorithm.ES512) || signingAlg.equals(JWSAlgorithm.HS512) || signingAlg.equals(JWSAlgorithm.RS512) || signingAlg.equals(JWSAlgorithm.PS512)) {
            hashAlg = "SHA-512";
        }

        if (hashAlg != null) {
            try {
                MessageDigest hasher = MessageDigest.getInstance(hashAlg);
                hasher.reset();
                hasher.update(bytes);

                byte[] hashBytes = hasher.digest();
                byte[] hashBytesLeftHalf = Arrays.copyOf(hashBytes, hashBytes.length / 2);

                return Base64URL.encode(hashBytesLeftHalf);
            } catch (NoSuchAlgorithmException e) {
                log.error("No such algorithm error: ", e);
            }
        }
        return null;
    }

    public static JsonObject getJSONObject(String requestString) {
        if (Strings.isNullOrEmpty(requestString)) {
            return null;
        } else {
            JsonElement el = JsonParser.parseString(requestString);
            if (el != null && el.isJsonObject()) {
                return el.getAsJsonObject();
            } else {
                return null;
            }
        }
    }

    public static void main(String[] args) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String password = "secret";
        String encodedPassword = passwordEncoder.encode(password);
        System.out.println();
        System.out.println("Password is         : " + password);
        System.out.println("Encoded Password is : " + encodedPassword);
        password = "password";
        encodedPassword = passwordEncoder.encode(password);
        System.out.println();
        System.out.println("Password is         : " + password);
        System.out.println("Encoded Password is : " + encodedPassword);
    }

}
