package in.bitanxen.poc.service.oauth2;

import com.nimbusds.jwt.JWT;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;

public interface OAuth2RequestService {
    OAuth2Request createOAuth2Request(ClientDetails client, TokenRequest tokenRequest, JWT assertion);
}
