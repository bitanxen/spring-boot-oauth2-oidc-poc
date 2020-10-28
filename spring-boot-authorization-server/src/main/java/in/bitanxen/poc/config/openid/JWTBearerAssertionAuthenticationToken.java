package in.bitanxen.poc.config.openid;

import com.nimbusds.jwt.JWT;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.text.ParseException;
import java.util.Collection;

@Log4j2
public class JWTBearerAssertionAuthenticationToken extends AbstractAuthenticationToken {

    private String subject;
    @Setter
    @Getter
    private JWT jwt;

    public JWTBearerAssertionAuthenticationToken(JWT jwt) {
        super(null);

        try {
            this.subject = jwt.getJWTClaimsSet().getSubject();
        } catch (ParseException e) {
            e.printStackTrace();
        }
        this.jwt = jwt;
        setAuthenticated(false);
    }

    public JWTBearerAssertionAuthenticationToken(JWT jwt, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        try {
            this.subject = jwt.getJWTClaimsSet().getSubject();
        } catch (ParseException e) {
            log.info("Unable to parse JWT");
        }
        this.jwt = jwt;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return jwt;
    }

    @Override
    public Object getPrincipal() {
        return subject;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        setJwt(null);
    }
}
