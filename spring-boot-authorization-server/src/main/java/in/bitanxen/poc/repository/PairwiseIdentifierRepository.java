package in.bitanxen.poc.repository;

import in.bitanxen.poc.model.user.PairwiseIdentifier;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PairwiseIdentifierRepository extends JpaRepository<PairwiseIdentifier, String> {
    PairwiseIdentifier findByUserSubAndSectorIdentifier(String userSub, String sectorIdentifier);
}
