package in.bitanxen.poc.service.scope;

import com.google.common.collect.Sets;
import in.bitanxen.poc.dto.scope.CreateSystemScopeDTO;
import in.bitanxen.poc.dto.scope.ScopeDTO;
import in.bitanxen.poc.model.scope.SystemScope;

import java.util.Collection;

import static in.bitanxen.poc.model.statics.SystemScopeType.REGISTRATION_TOKEN_SCOPE;
import static in.bitanxen.poc.model.statics.SystemScopeType.RESOURCE_TOKEN_SCOPE;

public interface SystemScopeService {

    Collection<SystemScope> reservedScopes =
            Sets.newHashSet(
                    new SystemScope(REGISTRATION_TOKEN_SCOPE.getValue(), REGISTRATION_TOKEN_SCOPE.getDescription(), REGISTRATION_TOKEN_SCOPE.getIcon(), REGISTRATION_TOKEN_SCOPE.isDefaultScope(), REGISTRATION_TOKEN_SCOPE.isRestricted()),
                    new SystemScope(RESOURCE_TOKEN_SCOPE.getValue(), RESOURCE_TOKEN_SCOPE.getDescription(), RESOURCE_TOKEN_SCOPE.getIcon(), RESOURCE_TOKEN_SCOPE.isDefaultScope(), RESOURCE_TOKEN_SCOPE.isRestricted())
            );

    Collection<SystemScope> getAll();
    Collection<SystemScope> getDefaults();
    Collection<SystemScope> getReserved();
    Collection<SystemScope> getRestricted();
    Collection<SystemScope> getUnrestricted();
    SystemScope getById(String id);
    SystemScope getByValue(String value);
    void remove(String id);
    SystemScope save(CreateSystemScopeDTO createSystemScope);
    Collection<SystemScope> fromStrings(Collection<String> scope);
    Collection<String> toStrings(Collection<SystemScope> scope);
    boolean scopesMatch(Collection<String> expected, Collection<String> actual);
    Collection<SystemScope> removeRestrictedAndReservedScopes(Collection<SystemScope> scopes);
    Collection<SystemScope> removeReservedScopes(Collection<SystemScope> scopes);
    Collection<ScopeDTO> getScopeFromString(Collection<String> scopes);
}
