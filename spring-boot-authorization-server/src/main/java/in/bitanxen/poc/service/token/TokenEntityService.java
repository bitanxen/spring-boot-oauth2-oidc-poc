package in.bitanxen.poc.service.token;

import in.bitanxen.poc.model.approved.ApprovedSite;
import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.token.AccessTokenEntity;
import in.bitanxen.poc.model.token.RefreshTokenEntity;

import java.util.List;
import java.util.Set;

public interface TokenEntityService {

    AccessTokenEntity saveAccessToken(AccessTokenEntity token);
    AccessTokenEntity getAccessTokenByValue(String accessTokenValue);
    AccessTokenEntity getAccessTokenById(String id);
    List<AccessTokenEntity> getAccessTokensForClient(ClientEntity client);
    Set<AccessTokenEntity> getAccessTokensByUserName(String name);
    Set<AccessTokenEntity> getAllAccessTokens();
    Set<AccessTokenEntity> getAllExpiredAccessTokens();
    //Set<AccessTokenEntity> getAccessTokensForResourceSet(ResourceSet rs);
    List<AccessTokenEntity> getAccessTokensForApprovedSite(ApprovedSite approvedSite);

    RefreshTokenEntity getRefreshTokenByValue(String refreshTokenValue);
    RefreshTokenEntity getRefreshTokenById(String Id);
    void removeRefreshToken(RefreshTokenEntity refreshToken);
    RefreshTokenEntity saveRefreshToken(RefreshTokenEntity refreshToken);
    void removeAccessToken(AccessTokenEntity accessToken);
    List<RefreshTokenEntity> getRefreshTokensForClient(ClientEntity client);
    Set<RefreshTokenEntity> getRefreshTokensByUserName(String name);
    Set<RefreshTokenEntity> getAllRefreshTokens();
    Set<RefreshTokenEntity> getAllExpiredRefreshTokens();

    void clearTokensForClient(ClientEntity client);
    void clearAccessTokensForRefreshToken(RefreshTokenEntity refreshToken);
}
