package in.bitanxen.poc.service.oidc;

import com.google.common.base.Strings;
import com.google.common.collect.Iterables;
import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.client.ClientRedirect;
import in.bitanxen.poc.model.user.PairwiseIdentifier;
import in.bitanxen.poc.model.user.UserInfo;
import in.bitanxen.poc.repository.PairwiseIdentifierRepository;
import in.bitanxen.poc.util.CommonUtil;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.transaction.Transactional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Log4j2
@Transactional
public class PairwiseIdentifierServiceImpl implements PairwiseIdentifierService {

    private final PairwiseIdentifierRepository pairwiseIdentifierRepository;

    public PairwiseIdentifierServiceImpl(PairwiseIdentifierRepository pairwiseIdentifierRepository) {
        this.pairwiseIdentifierRepository = pairwiseIdentifierRepository;
    }

    @Override
    public String getIdentifier(UserInfo userInfo, ClientEntity client) {
        String sectorIdentifier = null;

        if (!Strings.isNullOrEmpty(client.getSectorIdentifierUri())) {
            UriComponents uri = UriComponentsBuilder.fromUriString(client.getSectorIdentifierUri()).build();
            sectorIdentifier = uri.getHost(); // calculate based on the host component only
        } else {
            Set<String> redirectUris = client.getRedirectUris().stream().map(ClientRedirect::getRedirectUri).collect(Collectors.toSet());
            UriComponents uri = UriComponentsBuilder.fromUriString(Iterables.getOnlyElement(redirectUris)).build();
            sectorIdentifier = uri.getHost(); // calculate based on the host of the only redirect URI
        }

        if(sectorIdentifier == null) {
            return null;
        }

        PairwiseIdentifier pairwise = pairwiseIdentifierRepository.findByUserSubAndSectorIdentifier(userInfo.getSub(), sectorIdentifier);

        if (pairwise == null) {
            pairwise = new PairwiseIdentifier();
            pairwise.setIdentifier(CommonUtil.generateAlphaNumeric(16));
            pairwise.setUserSub(userInfo.getSub());
            pairwise.setSectorIdentifier(sectorIdentifier);
            pairwiseIdentifierRepository.save(pairwise);
        }

        return pairwise.getIdentifier();
    }
}
