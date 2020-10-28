package in.bitanxen.poc.service.watchlist;

import in.bitanxen.poc.dto.watchlist.CreateUpdateWhiteListSiteDTO;
import in.bitanxen.poc.exception.WatchlistException;
import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.watchlist.WhiteListSite;
import in.bitanxen.poc.model.watchlist.WhiteListSiteScope;
import in.bitanxen.poc.repository.WhiteListSiteRepository;
import in.bitanxen.poc.service.client.ClientEntityService;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Log4j2
@Transactional
public class WhiteListServiceImpl implements WhiteListService {

    private final WhiteListSiteRepository whiteListSiteRepository;
    private final ClientEntityService clientEntityService;

    public WhiteListServiceImpl(WhiteListSiteRepository whiteListSiteRepository, ClientEntityService clientEntityService) {
        this.whiteListSiteRepository = whiteListSiteRepository;
        this.clientEntityService = clientEntityService;
    }

    @Override
    public Collection<WhiteListSite> getAll() {
        return whiteListSiteRepository.findAll();
    }

    @Override
    public WhiteListSite getById(String id) {
        Optional<WhiteListSite> whiteListSiteOptional = whiteListSiteRepository.findById(id);
        if(!whiteListSiteOptional.isPresent()) {
            throw new WatchlistException("White List not found");
        }
        return whiteListSiteOptional.get();
    }

    @Override
    public WhiteListSite getByClientId(String clientId) {
        ClientEntity clientEntity = clientEntityService.getClientEntityByClientId(clientId);
        return whiteListSiteRepository.findByClient(clientEntity);
    }

    @Override
    public void remove(String siteId) {
        WhiteListSite whiteListSite = getById(siteId);
        whiteListSiteRepository.delete(whiteListSite);
    }

    @Override
    public WhiteListSite createWhiteListSite(CreateUpdateWhiteListSiteDTO whiteListedSite) {
        ClientEntity clientEntity = clientEntityService.getClientEntityByClientId(whiteListedSite.getClientId());
        WhiteListSite whiteListSite = new WhiteListSite();
        whiteListSite.setClient(clientEntity);
        whiteListSite.setCreatorUserId(whiteListedSite.getCreator());
        whiteListSite.setAllowedScopes(whiteListedSite.getScopes().stream().map(s -> new WhiteListSiteScope(whiteListSite, s)).collect(Collectors.toSet()));
        return whiteListSiteRepository.save(whiteListSite);
    }

    @Override
    public WhiteListSite updateWhiteListSite(String siteId, CreateUpdateWhiteListSiteDTO updateWhiteList) {
        WhiteListSite whiteListSite = getById(siteId);

        whiteListSite.getAllowedScopes().forEach(whiteListSiteScope -> {
            Optional<String> scopesOptional = updateWhiteList.getScopes().stream().filter(s -> s.equals(whiteListSiteScope.getScope())).findFirst();
            if(!scopesOptional.isPresent()) {
                remove(whiteListSiteScope.getId());
            }
        });

        updateWhiteList.getScopes().forEach(s -> {
            Optional<WhiteListSiteScope> scopesOptional = whiteListSite.getAllowedScopes().stream().filter(whiteListSiteScope -> whiteListSiteScope.getScope().equals(s)).findFirst();
            if(!scopesOptional.isPresent()) {
                whiteListSite.getAllowedScopes().add(new WhiteListSiteScope(whiteListSite, s));
            }
        });
        return whiteListSiteRepository.save(whiteListSite);
    }
}
