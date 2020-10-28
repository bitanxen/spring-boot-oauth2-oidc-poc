package in.bitanxen.poc.config.provider;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import in.bitanxen.poc.config.bean.ConfigurationProperty;
import in.bitanxen.poc.config.openid.JWTBearerAssertionAuthenticationToken;
import in.bitanxen.poc.dto.client.ClientEntityDTO;
import in.bitanxen.poc.exception.ClientNotFoundException;
import in.bitanxen.poc.model.statics.AuthMethod;
import in.bitanxen.poc.service.client.ClientEntityService;
import in.bitanxen.poc.service.jwt.ClientKeyCacheService;
import in.bitanxen.poc.service.jwt.signer.JWTSignerVerifierService;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

@Component
@Log4j2
public class JWTBearerAuthenticationProvider implements AuthenticationProvider {

    private static final GrantedAuthority ROLE_CLIENT = new SimpleGrantedAuthority("ROLE_CLIENT");

    private final ClientKeyCacheService validators;
    private final ClientEntityService clientEntityService;
    private final ConfigurationProperty configurationProperty;

    public JWTBearerAuthenticationProvider(ClientKeyCacheService validators, ClientEntityService clientEntityService, ConfigurationProperty configurationProperty) {
        this.validators = validators;
        this.clientEntityService = clientEntityService;
        this.configurationProperty = configurationProperty;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        int timeSkewAllowance = 300;
        JWTBearerAssertionAuthenticationToken jwtAuth = (JWTBearerAssertionAuthenticationToken)authentication;

        try {
            ClientEntityDTO clientEntity = clientEntityService.loadClientByClientId(jwtAuth.getName());

            JWT jwt = jwtAuth.getJwt();
            JWTClaimsSet jwtClaims = jwt.getJWTClaimsSet();

            if (!(jwt instanceof SignedJWT)) {
                throw new AuthenticationServiceException("Unsupported JWT type: " + jwt.getClass().getName());
            }

            // check the signature with nimbus
            SignedJWT jws = (SignedJWT) jwt;
            JWSAlgorithm alg = jws.getHeader().getAlgorithm();

            if (clientEntity.getTokenEndpointAuthSigningAlg() != null &&
                    !clientEntity.getTokenEndpointAuthSigningAlg().getName().equals(alg.getName())) {
                throw new AuthenticationServiceException("Client's registered token endpoint signing algorithm (" + clientEntity.getTokenEndpointAuthSigningAlg()
                        + ") does not match token's actual algorithm (" + alg.getName() + ")");
            }

            if (clientEntity.getTokenEndpointAuthMethod() == null ||
                    clientEntity.getTokenEndpointAuthMethod().equals(AuthMethod.NONE) ||
                    clientEntity.getTokenEndpointAuthMethod().equals(AuthMethod.SECRET_BASIC) ||
                    clientEntity.getTokenEndpointAuthMethod().equals(AuthMethod.SECRET_POST)) {

                // this client doesn't support this type of authentication
                throw new AuthenticationServiceException("Client does not support this authentication method.");

            } else if ((clientEntity.getTokenEndpointAuthMethod().equals(AuthMethod.PRIVATE_KEY) &&
                    (alg.equals(JWSAlgorithm.RS256)
                            || alg.equals(JWSAlgorithm.RS384)
                            || alg.equals(JWSAlgorithm.RS512)
                            || alg.equals(JWSAlgorithm.ES256)
                            || alg.equals(JWSAlgorithm.ES384)
                            || alg.equals(JWSAlgorithm.ES512)
                            || alg.equals(JWSAlgorithm.PS256)
                            || alg.equals(JWSAlgorithm.PS384)
                            || alg.equals(JWSAlgorithm.PS512)))
                    || (clientEntity.getTokenEndpointAuthMethod().equals(AuthMethod.SECRET_JWT) &&
                    (alg.equals(JWSAlgorithm.HS256)
                            || alg.equals(JWSAlgorithm.HS384)
                            || alg.equals(JWSAlgorithm.HS512)))) {

                // double-check the method is asymmetrical if we're in HEART mode
                if (configurationProperty.isHeartMode() && !clientEntity.getTokenEndpointAuthMethod().equals(AuthMethod.PRIVATE_KEY)) {
                    throw new AuthenticationServiceException("[HEART mode] Invalid authentication method");
                }

                JWTSignerVerifierService validator = validators.getValidator(clientEntity, alg);

                if (validator == null) {
                    throw new AuthenticationServiceException("Unable to create signature validator for client " + clientEntity.getClientId() + " and algorithm " + alg);
                }

                if (!validator.validateSignature(jws)) {
                    throw new AuthenticationServiceException("Signature did not validate for presented JWT authentication.");
                }
            } else {
                throw new AuthenticationServiceException("Unable to create signature validator for method " + clientEntity.getTokenEndpointAuthMethod() + " and algorithm " + alg);
            }

            if (jwtClaims.getIssuer() == null) {
                throw new AuthenticationServiceException("Assertion Token Issuer is null");
            } else if (!jwtClaims.getIssuer().equals(clientEntity.getClientId())){
                throw new AuthenticationServiceException("Issuers do not match, expected " + clientEntity.getClientId() + " got " + jwtClaims.getIssuer());
            }

            // check expiration
            if (jwtClaims.getExpirationTime() == null) {
                throw new AuthenticationServiceException("Assertion Token does not have required expiration claim");
            } else {
                // it's not null, see if it's expired
                Date now = new Date(System.currentTimeMillis() - (timeSkewAllowance * 1000));
                if (now.after(jwtClaims.getExpirationTime())) {
                    throw new AuthenticationServiceException("Assertion Token is expired: " + jwtClaims.getExpirationTime());
                }
            }

            // check not before
            if (jwtClaims.getNotBeforeTime() != null) {
                Date now = new Date(System.currentTimeMillis() + (timeSkewAllowance * 1000));
                if (now.before(jwtClaims.getNotBeforeTime())){
                    throw new AuthenticationServiceException("Assertion Token not valid untill: " + jwtClaims.getNotBeforeTime());
                }
            }

            // check issued at
            if (jwtClaims.getIssueTime() != null) {
                // since it's not null, see if it was issued in the future
                Date now = new Date(System.currentTimeMillis() + (timeSkewAllowance * 1000));
                if (now.before(jwtClaims.getIssueTime())) {
                    throw new AuthenticationServiceException("Assertion Token was issued in the future: " + jwtClaims.getIssueTime());
                }
            }

            // check audience
            if (jwtClaims.getAudience() == null) {
                throw new AuthenticationServiceException("Assertion token audience is null");
            } else if (!(jwtClaims.getAudience().contains(configurationProperty.getIssuer()) || jwtClaims.getAudience().contains(configurationProperty.getIssuer() + "token"))) {
                throw new AuthenticationServiceException("Audience does not match, expected " + configurationProperty.getIssuer() + " or " + (configurationProperty.getIssuer() + "token") + " got " + jwtClaims.getAudience());
            }

            // IFF we managed to get all the way down here, the token is valid

            // add in the ROLE_CLIENT authority
            Set<GrantedAuthority> authorities = new HashSet<>(clientEntity.getAuthorities());
            authorities.add(ROLE_CLIENT);

            return new JWTBearerAssertionAuthenticationToken(jwt, authorities);

        } catch (ClientNotFoundException clientNotFoundException) {
            throw new UsernameNotFoundException("Could not find client: " + jwtAuth.getName());
        } catch (ParseException e) {
            log.error("Failure during authentication, error was: ", e);
            throw new AuthenticationServiceException("Invalid JWT format");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JWTBearerAssertionAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
