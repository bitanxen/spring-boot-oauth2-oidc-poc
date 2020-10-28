package in.bitanxen.poc.repository;

import com.nimbusds.jwt.JWT;
import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.token.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface RefreshTokenEntityRepository extends JpaRepository<RefreshTokenEntity, String> {
    Optional<RefreshTokenEntity> findByJwt(JWT refreshTokenJWT);
    List<RefreshTokenEntity> findAllByClient(ClientEntity clientEntity);

    @Query("SELECT RT FROM RefreshTokenEntity RT WHERE RT.authenticationHolder.userAuth.name = :name ")
    Set<RefreshTokenEntity> fetchAllByUsername(String name);
}
