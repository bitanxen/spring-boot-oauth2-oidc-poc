package in.bitanxen.poc.repository;

import in.bitanxen.poc.model.authcode.AuthorizationCodeEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthorizationCodeEntityRepository extends JpaRepository<AuthorizationCodeEntity, String> {
    AuthorizationCodeEntity findByCode(String code);
}
