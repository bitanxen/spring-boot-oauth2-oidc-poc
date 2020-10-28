package in.bitanxen.poc.service.oauth2;

import com.google.common.collect.Sets;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.Set;

@Component
public class OAuth2RequestServiceImpl implements OAuth2RequestService {
    @Override
    public OAuth2Request createOAuth2Request(ClientDetails client, TokenRequest tokenRequest, JWT assertion) {
        try {
            JWTClaimsSet claims = assertion.getJWTClaimsSet();
            Set<String> scope = OAuth2Utils.parseParameterList(claims.getStringClaim("scope"));

            Set<String> resources = Sets.newHashSet(claims.getAudience());

            return new OAuth2Request(tokenRequest.getRequestParameters(), client.getClientId(), client.getAuthorities(), true, scope, resources, null, null, null);
        } catch (ParseException e) {
            return null;
        }
    }
}
