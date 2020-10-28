package in.bitanxen.poc.repository;

import in.bitanxen.poc.model.approved.ApprovedSite;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;

public interface ApprovedSiteRepository extends JpaRepository<ApprovedSite, String> {
    Collection<ApprovedSite> findAllByUserId(String userId);
    Collection<ApprovedSite> findAllByClientId(String clientId);
    Collection<ApprovedSite> findAllByClientIdAndUserId(String clientId, String userId);
}
