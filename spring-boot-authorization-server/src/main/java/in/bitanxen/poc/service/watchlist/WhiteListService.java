package in.bitanxen.poc.service.watchlist;

import in.bitanxen.poc.dto.watchlist.CreateUpdateWhiteListSiteDTO;
import in.bitanxen.poc.model.watchlist.WhiteListSite;

import java.util.Collection;

public interface WhiteListService {
    Collection<WhiteListSite> getAll();
    WhiteListSite getById(String id);
    WhiteListSite getByClientId(String clientId);
    void remove(String siteId);
    WhiteListSite createWhiteListSite(CreateUpdateWhiteListSiteDTO whitelistedSite);
    WhiteListSite updateWhiteListSite(String siteId, CreateUpdateWhiteListSiteDTO whitelistedSite);
}
