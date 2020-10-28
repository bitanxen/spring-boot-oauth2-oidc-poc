package in.bitanxen.poc.service.oauth2;

import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.token.AccessTokenEntity;
import in.bitanxen.poc.model.token.RefreshTokenEntity;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import java.util.List;
import java.util.Set;

public interface OAuth2TokenEntityService extends AuthorizationServerTokenServices, ResourceServerTokenServices {

    @Override
    AccessTokenEntity readAccessToken(String accessTokenValue);
    RefreshTokenEntity getRefreshToken(String refreshTokenValue);
    void revokeRefreshToken(RefreshTokenEntity refreshToken);
    void revokeAccessToken(AccessTokenEntity accessToken);
    List<AccessTokenEntity> getAccessTokensForClient(ClientEntity client);
    List<RefreshTokenEntity> getRefreshTokensForClient(ClientEntity client);
    void clearExpiredTokens();
    AccessTokenEntity saveAccessToken(AccessTokenEntity accessToken);
    RefreshTokenEntity saveRefreshToken(RefreshTokenEntity refreshToken);
    @Override
    AccessTokenEntity getAccessToken(OAuth2Authentication authentication);
    AccessTokenEntity getAccessTokenById(String id);
    RefreshTokenEntity getRefreshTokenById(String id);
    Set<AccessTokenEntity> getAllAccessTokensForUser(String name);
    Set<RefreshTokenEntity> getAllRefreshTokensForUser(String name);
    AccessTokenEntity getRegistrationAccessTokenForClient(ClientEntity client);

}
