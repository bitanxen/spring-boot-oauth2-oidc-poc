package in.bitanxen.poc.service.user;

import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.statics.SubjectType;
import in.bitanxen.poc.model.user.SystemUserInfo;
import in.bitanxen.poc.model.user.UserInfo;
import in.bitanxen.poc.repository.UserInfoRepository;
import in.bitanxen.poc.service.client.ClientEntityService;
import in.bitanxen.poc.service.oidc.PairwiseIdentifierService;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
@Log4j2
@Transactional
public class UserServiceImpl implements UserService {

    private final UserInfoRepository userInfoRepository;
    private final ClientEntityService clientEntityService;
    private final PairwiseIdentifierService pairwiseIdentifierService;

    public UserServiceImpl(UserInfoRepository userInfoRepository, ClientEntityService clientEntityService, PairwiseIdentifierService pairwiseIdentifierService) {
        this.userInfoRepository = userInfoRepository;
        this.clientEntityService = clientEntityService;
        this.pairwiseIdentifierService = pairwiseIdentifierService;
    }

    @Override
    public UserInfo getByUsername(String username) {
        return userInfoRepository.findByPreferredUsername(username);
    }

    @Override
    public UserInfo getByUsernameAndClientId(String username, String clientId) {
        ClientEntity client = clientEntityService.getClientEntityByClientId(clientId);
        UserInfo userInfo = getByUsername(username);

        if (client == null || userInfo == null) {
            return null;
        }

        if (SubjectType.PAIRWISE.equals(client.getSubjectType())) {
            String pairwiseSub = pairwiseIdentifierService.getIdentifier(userInfo, client);

            SystemUserInfo systemUserInfo = (SystemUserInfo) userInfo;
            systemUserInfo.setSub(pairwiseSub);
            userInfoRepository.save(systemUserInfo);
        }

        return userInfo;
    }

    @Override
    public UserInfo getByEmailAddress(String email) {
        return userInfoRepository.findByEmail(email);
    }
}
