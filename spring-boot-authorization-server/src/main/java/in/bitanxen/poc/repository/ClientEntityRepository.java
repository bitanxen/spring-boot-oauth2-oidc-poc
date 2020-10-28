package in.bitanxen.poc.repository;

import in.bitanxen.poc.model.client.ClientEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ClientEntityRepository extends JpaRepository<ClientEntity, String> {
    Optional<ClientEntity> findByClientId(String clientId);
}
