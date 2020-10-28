package in.bitanxen.poc.service.token;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import in.bitanxen.poc.exception.TokenException;
import in.bitanxen.poc.model.approved.ApprovedSite;
import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.token.AccessTokenEntity;
import in.bitanxen.poc.model.token.RefreshTokenEntity;
import in.bitanxen.poc.repository.AccessTokenEntityRepository;
import in.bitanxen.poc.repository.RefreshTokenEntityRepository;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Log4j2
public class TokenEntityServiceImpl implements TokenEntityService {

    private final AccessTokenEntityRepository accessTokenRepository;
    private final RefreshTokenEntityRepository refreshTokenRepository;

    public TokenEntityServiceImpl(AccessTokenEntityRepository accessTokenRepository, RefreshTokenEntityRepository refreshTokenRepository) {
        this.accessTokenRepository = accessTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Override
    public AccessTokenEntity saveAccessToken(AccessTokenEntity token) {
        return accessTokenRepository.save(token);
    }

    @Override
    public AccessTokenEntity getAccessTokenByValue(String accessTokenValue) {
        JWT jwt = null;
        try {
            jwt = JWTParser.parse(accessTokenValue);
        } catch (ParseException e) {
            throw new InvalidTokenException("Access token is invalid JWT : "+e.getLocalizedMessage());
        }
        Optional<AccessTokenEntity> accessTokenEntityOptional = accessTokenRepository.findByJwtValue(jwt);
        if(!accessTokenEntityOptional.isPresent()) {
            throw new TokenException("Access Token not found");
        }
        return accessTokenEntityOptional.get();
    }

    @Override
    public AccessTokenEntity getAccessTokenById(String id) {
        Optional<AccessTokenEntity> accessTokenEntityOptional = accessTokenRepository.findById(id);
        if(!accessTokenEntityOptional.isPresent()) {
            throw new TokenException("Access Token not found");
        }
        return accessTokenEntityOptional.get();
    }

    @Override
    public List<AccessTokenEntity> getAccessTokensForClient(ClientEntity client) {
        return accessTokenRepository.findAllByClient(client);
    }

    @Override
    public Set<AccessTokenEntity> getAccessTokensByUserName(String name) {
        return accessTokenRepository.fetchAllByUsername(name);
    }

    @Override
    public Set<AccessTokenEntity> getAllAccessTokens() {
        return new HashSet<>(accessTokenRepository.findAll());
    }

    @Override
    public Set<AccessTokenEntity> getAllExpiredAccessTokens() {
        return getAllAccessTokens().stream().filter(AccessTokenEntity::isExpired).collect(Collectors.toSet());
    }

    @Override
    public List<AccessTokenEntity> getAccessTokensForApprovedSite(ApprovedSite approvedSite) {
        return accessTokenRepository.findAllByApprovedSite(approvedSite);
    }

    @Override
    public RefreshTokenEntity getRefreshTokenByValue(String refreshTokenValue) {
        JWT jwt = null;
        try {
            jwt = JWTParser.parse(refreshTokenValue);
        } catch (ParseException e) {
            throw new InvalidTokenException("Refresh token is invalid JWT : "+e.getLocalizedMessage());
        }
        Optional<RefreshTokenEntity> refreshTokenEntityOptional = refreshTokenRepository.findByJwt(jwt);
        if(!refreshTokenEntityOptional.isPresent()) {
            throw new TokenException("Refresh Token not found");
        }
        return refreshTokenEntityOptional.get();
    }

    @Override
    public RefreshTokenEntity getRefreshTokenById(String Id) {
        Optional<RefreshTokenEntity> refreshTokenEntityOptional = refreshTokenRepository.findById(Id);
        if(!refreshTokenEntityOptional.isPresent()) {
            throw new TokenException("Refresh Token not found");
        }
        return refreshTokenEntityOptional.get();
    }

    @Override
    public void removeRefreshToken(RefreshTokenEntity refreshToken) {
        refreshTokenRepository.delete(refreshToken);
    }

    @Override
    public RefreshTokenEntity saveRefreshToken(RefreshTokenEntity refreshToken) {
        return refreshTokenRepository.save(refreshToken);
    }

    @Override
    public void removeAccessToken(AccessTokenEntity accessToken) {
        accessTokenRepository.delete(accessToken);
    }

    @Override
    public List<RefreshTokenEntity> getRefreshTokensForClient(ClientEntity client) {
        return refreshTokenRepository.findAllByClient(client);
    }

    @Override
    public Set<RefreshTokenEntity> getRefreshTokensByUserName(String name) {
        return refreshTokenRepository.fetchAllByUsername(name);
    }

    @Override
    public Set<RefreshTokenEntity> getAllRefreshTokens() {
        return new HashSet<>(refreshTokenRepository.findAll());
    }

    @Override
    public Set<RefreshTokenEntity> getAllExpiredRefreshTokens() {
        return getAllRefreshTokens().stream().filter(RefreshTokenEntity::isExpired).collect(Collectors.toSet());
    }

    @Override
    public void clearTokensForClient(ClientEntity client) {
        List<AccessTokenEntity> accessTokensForClient = getAccessTokensForClient(client);
        for(AccessTokenEntity accessTokenEntity : accessTokensForClient) {
            removeAccessToken(accessTokenEntity);
        }

        List<RefreshTokenEntity> refreshTokensForClient = getRefreshTokensForClient(client);
        for(RefreshTokenEntity refreshTokenEntity : refreshTokensForClient) {
            removeRefreshToken(refreshTokenEntity);
        }
    }

    @Override
    public void clearAccessTokensForRefreshToken(RefreshTokenEntity refreshToken) {
        RefreshTokenEntity refreshTokenByValue = getRefreshTokenByValue(refreshToken.getValue());
        Set<AccessTokenEntity> accessTokenEntities = accessTokenRepository.fetchAllByRefreshToken(refreshTokenByValue);
        for(AccessTokenEntity accessTokenEntity : accessTokenEntities) {
            removeAccessToken(accessTokenEntity);
        }
    }
}
