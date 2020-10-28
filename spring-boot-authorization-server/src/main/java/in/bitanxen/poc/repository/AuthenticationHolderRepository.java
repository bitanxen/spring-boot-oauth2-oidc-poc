package in.bitanxen.poc.repository;

import in.bitanxen.poc.model.authholder.AuthenticationHolderEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Collection;

public interface AuthenticationHolderRepository extends JpaRepository<AuthenticationHolderEntity, String> {

    @Query(value =  "SELECT A "+
                    "  FROM AuthenticationHolderEntity A "+
                    " WHERE A NOT IN (SELECT AT.authenticationHolder FROM AccessTokenEntity AT) "+
                    "   AND A NOT IN (SELECT RT.authenticationHolder FROM RefreshTokenEntity RT) "+
                    "   AND A NOT IN (SELECT AC.authenticationHolder FROM AuthorizationCodeEntity AC )")
    Collection<AuthenticationHolderEntity> getOrphanedAuthenticationHolders();
}
