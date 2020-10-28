package in.bitanxen.poc.service.auth;

import in.bitanxen.poc.model.authholder.AuthenticationHolderEntity;

import java.util.Collection;
import java.util.List;

public interface AuthenticationHolderService {
    List<AuthenticationHolderEntity> getAll();
    AuthenticationHolderEntity getById(String id);
    void remove(String id);
    AuthenticationHolderEntity save(AuthenticationHolderEntity a);
    Collection<AuthenticationHolderEntity> getOrphanedAuthenticationHolders();
}
