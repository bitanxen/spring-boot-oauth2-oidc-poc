package in.bitanxen.poc.repository;

import in.bitanxen.poc.model.watchlist.BlackListSite;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface BlackListSiteRepository extends JpaRepository<BlackListSite, String> {
    Optional<BlackListSite> findByUri(String uri);
}
