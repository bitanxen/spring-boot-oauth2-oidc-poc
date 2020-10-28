package in.bitanxen.poc.service.watchlist;

import in.bitanxen.poc.dto.watchlist.ApprovedSiteDTO;
import in.bitanxen.poc.dto.watchlist.CreateUpdateApprovedSiteDTO;
import in.bitanxen.poc.model.approved.ApprovedSite;
import in.bitanxen.poc.model.token.AccessTokenEntity;
import org.springframework.security.oauth2.provider.ClientDetails;

import java.util.Collection;
import java.util.List;

public interface ApprovedSiteService {
    Collection<ApprovedSite> getAll();
    ApprovedSiteDTO createApprovedSite(CreateUpdateApprovedSiteDTO createApprovedSite);
    Collection<ApprovedSiteDTO> getByClientIdAndUserId(String clientId, String userId);
    ApprovedSite getById(String id);
    void remove(String id);
    Collection<ApprovedSite> getByUserId(String userId);
    Collection<ApprovedSite> getByClientId(String clientId);
    void clearApprovedSitesForClient(ClientDetails client);
    void clearExpiredSites();
    ApprovedSiteDTO updateApprovedSite(String siteId, CreateUpdateApprovedSiteDTO updateApprovedSite);
    List<AccessTokenEntity> getApprovedAccessTokens(ApprovedSite approvedSite);
}
