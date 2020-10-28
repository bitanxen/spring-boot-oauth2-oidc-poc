package in.bitanxen.poc.repository;

import com.nimbusds.jwt.JWT;
import in.bitanxen.poc.model.approved.ApprovedSite;
import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.token.AccessTokenEntity;
import in.bitanxen.poc.model.token.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface AccessTokenEntityRepository extends JpaRepository<AccessTokenEntity, String> {
    Optional<AccessTokenEntity> findByJwtValue(JWT jwtValue);
    List<AccessTokenEntity> findAllByClient(ClientEntity clientEntity);

    @Query("SELECT AT FROM AccessTokenEntity AT WHERE AT.authenticationHolder.userAuth.name = :name ")
    Set<AccessTokenEntity> fetchAllByUsername(String name);

    List<AccessTokenEntity> findAllByApprovedSite(ApprovedSite approvedSite);

    @Query("SELECT AT FROM AccessTokenEntity AT WHERE AT.refreshToken = ?1")
    Set<AccessTokenEntity> fetchAllByRefreshToken(RefreshTokenEntity refreshTokenEntity);
}
