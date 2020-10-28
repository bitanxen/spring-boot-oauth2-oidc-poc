package in.bitanxen.poc.service.oidc;

import com.nimbusds.jwt.JWT;
import in.bitanxen.poc.dto.client.ClientEntityDTO;
import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.token.AccessTokenEntity;
import org.springframework.security.oauth2.provider.OAuth2Request;

import java.time.LocalDateTime;

public interface OIDCTokenService {
    JWT createIdToken(ClientEntityDTO client, OAuth2Request request, LocalDateTime issueTime, String sub, AccessTokenEntity accessToken);
    AccessTokenEntity createRegistrationAccessToken(ClientEntity client);
    AccessTokenEntity createResourceAccessToken(ClientEntity client);
    AccessTokenEntity rotateRegistrationAccessTokenForClient(ClientEntity client);
}
