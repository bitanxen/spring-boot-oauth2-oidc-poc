package in.bitanxen.poc.config.bean;

import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStreamReader;
import java.text.ParseException;
import java.util.List;

@Log4j2
@NoArgsConstructor
@Getter
public class JWKSetKeyStore {

    private JWKSet jwkSet;
    private Resource location;

    public JWKSetKeyStore(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    public JWKSetKeyStore(Resource resource) {
        this.location = resource;
        initializeJwkSet();
    }

    private void initializeJwkSet() {
        if (location == null) {
            throw new IllegalArgumentException("Key store location is null");
        }

        if (location.exists() && location.isReadable()) {
            try {
                String s = CharStreams.toString(new InputStreamReader(location.getInputStream(), Charsets.UTF_8));
                jwkSet = JWKSet.parse(s);
            } catch (IOException e) {
                throw new IllegalArgumentException("Key Set resource could not be read: " + location);
            } catch (ParseException e) {
                throw new IllegalArgumentException("Key Set resource could not be parsed: " + location);
            }
        } else {
            throw new IllegalArgumentException("Key Set resource could not be read: " + location);
        }
    }

    public List<JWK> getKeys() {
        if (jwkSet == null) {
            initializeJwkSet();
        }
        return jwkSet.getKeys();
    }
}
