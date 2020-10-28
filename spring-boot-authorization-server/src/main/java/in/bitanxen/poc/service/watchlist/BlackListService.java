package in.bitanxen.poc.service.watchlist;

import in.bitanxen.poc.dto.watchlist.CreateBlacklistSiteDTO;
import in.bitanxen.poc.dto.watchlist.UpdateBlacklistedSiteDTO;
import in.bitanxen.poc.model.watchlist.BlackListSite;

import java.util.List;

public interface BlackListService {

    List<BlackListSite> getAllEntries();
    List<BlackListSite> getAllBlacklistedSite();
    BlackListSite getBlacklistedSiteById(String id);
    BlackListSite createdBlacklistSite(CreateBlacklistSiteDTO createBlacklistSite);
    BlackListSite updateBlacklistedSite(String blackListId, UpdateBlacklistedSiteDTO updateBlacklistedSite);
    void deleteBlacklistedSite(String id);
    boolean isSiteBlacklisted(String siteUri);
}
