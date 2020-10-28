package in.bitanxen.poc.repository;

import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.watchlist.WhiteListSite;
import org.springframework.data.jpa.repository.JpaRepository;

public interface WhiteListSiteRepository extends JpaRepository<WhiteListSite, String> {
    WhiteListSite findByClient(ClientEntity clientEntity);
}
