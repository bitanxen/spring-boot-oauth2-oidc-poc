package in.bitanxen.poc.service.watchlist;

import in.bitanxen.poc.dto.watchlist.CreateBlacklistSiteDTO;
import in.bitanxen.poc.dto.watchlist.UpdateBlacklistedSiteDTO;
import in.bitanxen.poc.exception.WatchlistException;
import in.bitanxen.poc.model.watchlist.BlackListSite;
import in.bitanxen.poc.repository.BlackListSiteRepository;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Transactional
@Log4j2
public class BlackListServiceImpl implements BlackListService {

    @Autowired
    private BlackListSiteRepository blackListSiteRepository;


    @Override
    public List<BlackListSite> getAllEntries() {
        return blackListSiteRepository.findAll();
    }

    @Override
    public List<BlackListSite> getAllBlacklistedSite() {
        return getAllEntries().stream().filter(BlackListSite::isEnabled).collect(Collectors.toList());
    }

    @Override
    public BlackListSite getBlacklistedSiteById(String id) {
        Optional<BlackListSite> blackListSiteOptional = blackListSiteRepository.findById(id);
        if(!blackListSiteOptional.isPresent()) {
            throw new WatchlistException("Blacklist information not found");
        }
        return blackListSiteOptional.get();
    }

    @Override
    public BlackListSite createdBlacklistSite(CreateBlacklistSiteDTO createBlacklistSite) {
        BlackListSite blackListSite = new BlackListSite();
        blackListSite.setUri(createBlacklistSite.getSiteUrl());
        blackListSite.setEnabled(true);
        blackListSite.setCreatedAt(LocalDateTime.now());
        return blackListSiteRepository.save(blackListSite);
    }

    @Override
    public BlackListSite updateBlacklistedSite(String blackListId, UpdateBlacklistedSiteDTO updateBlacklistedSite) {
        BlackListSite blackListSite = getBlacklistedSiteById(blackListId);
        blackListSite.setUri(updateBlacklistedSite.getSiteUrl());
        blackListSite.setEnabled(updateBlacklistedSite.isEnabled());
        return blackListSiteRepository.save(blackListSite);
    }

    @Override
    public void deleteBlacklistedSite(String id) {
        BlackListSite blackListSite = getBlacklistedSiteById(id);
        blackListSiteRepository.delete(blackListSite);
    }

    @Override
    public boolean isSiteBlacklisted(String siteUri) {
        return blackListSiteRepository.findByUri(siteUri).isPresent();
    }
}
