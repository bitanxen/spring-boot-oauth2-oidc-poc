package in.bitanxen.poc.service.watchlist;

import in.bitanxen.poc.dto.watchlist.ApprovedSiteDTO;
import in.bitanxen.poc.dto.watchlist.ApprovedSiteScopeDTO;
import in.bitanxen.poc.dto.watchlist.CreateUpdateApprovedSiteDTO;
import in.bitanxen.poc.exception.ApprovedSiteException;
import in.bitanxen.poc.model.approved.ApprovedSite;
import in.bitanxen.poc.model.approved.ApprovedSiteScope;
import in.bitanxen.poc.model.token.AccessTokenEntity;
import in.bitanxen.poc.repository.ApprovedSiteRepository;
import in.bitanxen.poc.service.token.TokenEntityService;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Log4j2
@Transactional
public class ApprovedSiteServiceImpl implements ApprovedSiteService {

    private final ApprovedSiteRepository approvedSiteRepository;
    private final TokenEntityService tokenEntityService;

    public ApprovedSiteServiceImpl(ApprovedSiteRepository approvedSiteRepository, TokenEntityService tokenEntityService) {
        this.approvedSiteRepository = approvedSiteRepository;
        this.tokenEntityService = tokenEntityService;
    }

    @Override
    public Collection<ApprovedSite> getAll() {
        return approvedSiteRepository.findAll();
    }

    @Override
    public ApprovedSiteDTO createApprovedSite(CreateUpdateApprovedSiteDTO createApprovedSite) {
        LocalDateTime now = LocalDateTime.now();
        ApprovedSite approvedSite = new ApprovedSite();
        approvedSite.setUserId(createApprovedSite.getUserId());
        approvedSite.setClientId(createApprovedSite.getClientId());
        approvedSite.setCreationDate(now);
        approvedSite.setAccessDate(now);
        approvedSite.setTimeoutDate(createApprovedSite.getTimeoutDate());
        approvedSite.setAllowedScopes(createApprovedSite.getScopes().stream().map(s -> new ApprovedSiteScope(approvedSite, s)).collect(Collectors.toSet()));
        return convertIntoDTO(approvedSiteRepository.save(approvedSite));
    }

    @Override
    public Collection<ApprovedSiteDTO> getByClientIdAndUserId(String clientId, String userId) {
        return approvedSiteRepository.findAllByClientIdAndUserId(clientId, userId).stream().map(this::convertIntoDTO).collect(Collectors.toList());
    }

    @Override
    public ApprovedSite getById(String id) {
        Optional<ApprovedSite> approvedSiteOptional = approvedSiteRepository.findById(id);
        if(!approvedSiteOptional.isPresent()) {
            throw new ApprovedSiteException("Approved Site not found");
        }
        return approvedSiteOptional.get();
    }

    @Override
    public void remove(String id) {
        ApprovedSite approvedSite = getById(id);
        List<AccessTokenEntity> accessTokensForApprovedSite = tokenEntityService.getAccessTokensForApprovedSite(approvedSite);

        for (AccessTokenEntity token : accessTokensForApprovedSite) {
            if (token.getRefreshToken() != null) {
                tokenEntityService.removeRefreshToken(token.getRefreshToken());
            }
            tokenEntityService.removeAccessToken(token);
        }
        approvedSiteRepository.delete(approvedSite);
    }

    @Override
    public Collection<ApprovedSite> getByUserId(String userId) {
        return approvedSiteRepository.findAllByUserId(userId);
    }

    @Override
    public Collection<ApprovedSite> getByClientId(String clientId) {
        return approvedSiteRepository.findAllByClientId(clientId);
    }

    @Override
    public void clearApprovedSitesForClient(ClientDetails client) {
        Collection<ApprovedSite> approvedSites = getByClientId(client.getClientId());
        if (approvedSites != null) {
            for (ApprovedSite approvedSite : approvedSites) {
                remove(approvedSite.getId());
            }
        }
    }

    @Override
    public void clearExpiredSites() {
        Set<ApprovedSite> expiredSites = getAll().stream()
                .filter(approvedSite -> approvedSite.getTimeoutDate().isAfter(LocalDateTime.now()))
                .collect(Collectors.toSet());

        for (ApprovedSite expired : expiredSites) {
            remove(expired.getId());
        }
    }

    @Override
    public ApprovedSiteDTO updateApprovedSite(String siteId, CreateUpdateApprovedSiteDTO updateApprovedSite) {
        ApprovedSite approvedSite = getById(siteId);
        approvedSite.setAccessDate(LocalDateTime.now());
        approvedSite.setTimeoutDate(updateApprovedSite.getTimeoutDate());
        return convertIntoDTO(approvedSiteRepository.save(approvedSite));
    }

    @Override
    public List<AccessTokenEntity> getApprovedAccessTokens(ApprovedSite approvedSite) {
        return tokenEntityService.getAccessTokensForApprovedSite(approvedSite);
    }

    private ApprovedSiteDTO convertIntoDTO(ApprovedSite approvedSite) {
        if(approvedSite == null) {
            return null;
        }

        return ApprovedSiteDTO.builder()
                .id(approvedSite.getId())
                .userId(approvedSite.getUserId())
                .clientId(approvedSite.getClientId())
                .accessDate(approvedSite.getAccessDate())
                .creationDate(approvedSite.getCreationDate())
                .timeoutDate(approvedSite.getTimeoutDate())
                .approvedSiteScopes(
                        approvedSite.getAllowedScopes()
                                .stream()
                                .map(s -> ApprovedSiteScopeDTO.builder()
                                        .id(s.getId())
                                        .approvedSiteId(approvedSite.getId())
                                        .scope(s.getScope())
                                        .build())
                        .collect(Collectors.toList())
                )
                .build();

    }
}
