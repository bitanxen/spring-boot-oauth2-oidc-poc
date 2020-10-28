package in.bitanxen.poc.repository;

import in.bitanxen.poc.model.scope.SystemScope;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.Optional;

public interface SystemScopeRepository extends JpaRepository<SystemScope, String> {
    Optional<SystemScope> findByValue(String value);
    Collection<SystemScope> findByValueIn(Collection<String> values);
}
