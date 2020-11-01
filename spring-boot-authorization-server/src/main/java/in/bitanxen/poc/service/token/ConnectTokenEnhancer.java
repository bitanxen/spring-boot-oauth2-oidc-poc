package in.bitanxen.poc.service.token;

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import in.bitanxen.poc.config.bean.ConfigurationProperty;
import in.bitanxen.poc.dto.client.ClientEntityDTO;
import in.bitanxen.poc.model.statics.SystemScopeType;
import in.bitanxen.poc.model.token.AccessTokenEntity;
import in.bitanxen.poc.model.user.UserInfo;
import in.bitanxen.poc.service.client.ClientEntityService;
import in.bitanxen.poc.service.jwt.signer.JWTSignerVerifierService;
import in.bitanxen.poc.service.oidc.OIDCTokenService;
import in.bitanxen.poc.service.user.UserService;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;

@Service
@Log4j2
public class ConnectTokenEnhancer implements TokenEnhancer {

    private final ConfigurationProperty configurationProperty;
    private final JWTSignerVerifierService jwtSignerVerifierService;
    private final ClientEntityService clientEntityService;
    private final OIDCTokenService oidcTokenService;
    private final UserService userService;

    public ConnectTokenEnhancer(ConfigurationProperty configurationProperty, JWTSignerVerifierService jwtSignerVerifierService,
                                ClientEntityService clientEntityService, OIDCTokenService oidcTokenService, UserService userService) {
        this.configurationProperty = configurationProperty;
        this.jwtSignerVerifierService = jwtSignerVerifierService;
        this.clientEntityService = clientEntityService;
        this.oidcTokenService = oidcTokenService;
        this.userService = userService;
    }


    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        AccessTokenEntity token = (AccessTokenEntity) accessToken;
        OAuth2Request originalAuthRequest = authentication.getOAuth2Request();
        ClientEntityDTO client = clientEntityService.loadClientByClientId(originalAuthRequest.getClientId());

        JWTClaimsSet.Builder jwtClaims = new JWTClaimsSet.Builder()
                .claim("azp", client.getClientId())
                .issuer(configurationProperty.getIssuer())
                .issueTime(new Date())
                .expirationTime(token.getExpiration())
                .subject(authentication.getName())
                .jwtID(UUID.randomUUID().toString());

        String audience = (String) originalAuthRequest.getExtensions().get("aud");
        if (!Strings.isNullOrEmpty(audience)) {
            jwtClaims.audience(Lists.newArrayList(audience));
        }

        JWTClaimsSet claims = jwtClaims.build();
        JWSAlgorithm signingAlg = jwtSignerVerifierService.getDefaultSigningAlgorithm();

        JWSHeader header = new JWSHeader.Builder(signingAlg).keyID(jwtSignerVerifierService.getDefaultSignerKeyId()).build();
        SignedJWT signed = new SignedJWT(header, claims);
        jwtSignerVerifierService.signJwt(signed, signingAlg);

        token.setJwtValue(signed);

        if (originalAuthRequest.getScope().contains(SystemScopeType.OPENID_SCOPE.getValue())
                && !authentication.isClientOnly()) {

            String username = authentication.getName();
            UserInfo userInfo = userService.getUserInfoByUsernameAndClientId(username, client.getClientId());

            if (userInfo != null) {
                LocalDateTime issueTime = claims.getIssueTime().toInstant()
                        .atZone(ZoneId.systemDefault())
                        .toLocalDateTime();

                JWT idToken = oidcTokenService.createIdToken(client, originalAuthRequest, issueTime, userInfo.getSub(), token);
                token.setIdToken(idToken);
            } else {
                log.warn("Request for ID token when no user is present.");
            }
        }
        return token;
    }
}
