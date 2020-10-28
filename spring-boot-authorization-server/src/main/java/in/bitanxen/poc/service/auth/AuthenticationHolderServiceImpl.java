package in.bitanxen.poc.service.auth;

import in.bitanxen.poc.exception.AuthenticationHolderException;
import in.bitanxen.poc.model.authholder.AuthenticationHolderEntity;
import in.bitanxen.poc.repository.AuthenticationHolderRepository;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Service
@Log4j2
@Transactional
public class AuthenticationHolderServiceImpl implements AuthenticationHolderService {

    private final AuthenticationHolderRepository authenticationHolderRepository;

    public AuthenticationHolderServiceImpl(AuthenticationHolderRepository authenticationHolderRepository) {
        this.authenticationHolderRepository = authenticationHolderRepository;
    }

    @Override
    public List<AuthenticationHolderEntity> getAll() {
        return authenticationHolderRepository.findAll();
    }

    @Override
    public AuthenticationHolderEntity getById(String id) {
        Optional<AuthenticationHolderEntity> holderEntityOptional = authenticationHolderRepository.findById(id);
        if(!holderEntityOptional.isPresent()) {
            throw new AuthenticationHolderException("No Authentication Holder Entity found");
        }
        return holderEntityOptional.get();
    }

    @Override
    public void remove(String id) {
        AuthenticationHolderEntity authenticationHolderEntity = getById(id);
        authenticationHolderRepository.delete(authenticationHolderEntity);
    }

    @Override
    public AuthenticationHolderEntity save(AuthenticationHolderEntity authenticationHolderEntity) {
        return authenticationHolderRepository.save(authenticationHolderEntity);
    }

    @Override
    public Collection<AuthenticationHolderEntity> getOrphanedAuthenticationHolders() {
        return authenticationHolderRepository.getOrphanedAuthenticationHolders();
    }
}
