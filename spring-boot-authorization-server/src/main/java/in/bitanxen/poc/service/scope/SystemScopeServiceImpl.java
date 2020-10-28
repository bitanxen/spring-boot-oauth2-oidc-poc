package in.bitanxen.poc.service.scope;

import in.bitanxen.poc.dto.scope.CreateSystemScopeDTO;
import in.bitanxen.poc.dto.scope.ScopeDTO;
import in.bitanxen.poc.exception.ScopeException;
import in.bitanxen.poc.model.scope.SystemScope;
import in.bitanxen.poc.repository.SystemScopeRepository;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

@Service
@Transactional
@Log4j2
public class SystemScopeServiceImpl implements SystemScopeService {

    private final SystemScopeRepository systemScopeRepository;

    public SystemScopeServiceImpl(SystemScopeRepository systemScopeRepository) {
        this.systemScopeRepository = systemScopeRepository;
    }

    private final Predicate<SystemScope> isDefault = input -> (input != null && input.isDefaultScope());

    private final Predicate<SystemScope> isRestricted = input -> (input != null && input.isRestricted());

    private final Predicate<SystemScope> isReserved = input -> (input != null && getReserved().contains(input));

    @Override
    public Collection<SystemScope> getAll() {
        return systemScopeRepository.findAll();
    }

    @Override
    public Collection<SystemScope> getDefaults() {
        return getAll().stream().filter(isDefault).collect(Collectors.toSet());
    }

    @Override
    public Collection<SystemScope> getReserved() {
        return reservedScopes;
    }

    @Override
    public Collection<SystemScope> getRestricted() {
        return getAll().stream().filter(isRestricted).collect(Collectors.toSet());
    }

    @Override
    public Collection<SystemScope> getUnrestricted() {
        return getAll().stream().filter(isRestricted.negate()).collect(Collectors.toSet());
    }

    @Override
    public SystemScope getById(String id) {
        Optional<SystemScope> systemScopeOptional = systemScopeRepository.findById(id);
        if(!systemScopeOptional.isPresent()) {
            throw new ScopeException("Scope not found");
        }
        return systemScopeOptional.get();
    }

    @Override
    public SystemScope getByValue(String value) {
        Optional<SystemScope> systemScopeOptional = systemScopeRepository.findByValue(value);
        if(!systemScopeOptional.isPresent()) {
            throw new ScopeException("Scope not found");
        }
        return systemScopeOptional.get();
    }

    @Override
    public void remove(String id) {
        SystemScope systemScope = getById(id);
        systemScopeRepository.delete(systemScope);
    }

    @Override
    public SystemScope save(CreateSystemScopeDTO createSystemScope) {
        SystemScope systemScope = new SystemScope(createSystemScope.getScope(), createSystemScope.getDescription(),
                createSystemScope.getIcon(), createSystemScope.isDefaultScope(), createSystemScope.isRestrictedScope());
        return systemScopeRepository.save(systemScope);
    }

    @Override
    public Collection<SystemScope> fromStrings(Collection<String> scope) {
        if (scope == null) {
            return null;
        }
        return scope.stream().map(s -> {
            Optional<SystemScope> reservedScopeOptional = getReserved().stream().filter(rs -> rs.getValue().equals(s)).findFirst();
            if (reservedScopeOptional.isPresent()) {
                return reservedScopeOptional.get();
            }

            Optional<SystemScope> systemScopeOptional = systemScopeRepository.findByValue(s);

            return systemScopeOptional.orElse(null);
        }).collect(Collectors.toSet());
    }

    @Override
    public Collection<String> toStrings(Collection<SystemScope> scope) {
        if (scope == null) {
            return null;
        }
        return scope.stream().map(SystemScope::getValue).collect(Collectors.toSet());
    }

    @Override
    public boolean scopesMatch(Collection<String> expected, Collection<String> actual) {
        Set<String> setA = new HashSet<>(expected);
        Set<String> setB = new HashSet<>(actual);
        return setA.containsAll(setB) && setB.containsAll(setA);
    }

    @Override
    public Collection<SystemScope> removeRestrictedAndReservedScopes(Collection<SystemScope> scopes) {
        return scopes.stream().filter(isRestricted.negate()).filter(isReserved.negate()).collect(Collectors.toSet());
    }

    @Override
    public Collection<SystemScope> removeReservedScopes(Collection<SystemScope> scopes) {
        return scopes.stream().filter(isReserved.negate()).collect(Collectors.toSet());
    }

    @Override
    public Collection<ScopeDTO> getScopeFromString(Collection<String> scopes) {
        return systemScopeRepository.findByValueIn(scopes).stream().map(this::convertIntoDTO).collect(Collectors.toSet());
    }

    private ScopeDTO convertIntoDTO(SystemScope systemScope) {
        if(systemScope == null) {
            return null;
        }
        return ScopeDTO.builder()
                .scopeId(systemScope.getId())
                .scopeValue(systemScope.getValue())
                .scopeDescription(systemScope.getDescription())
                .scopeIcon(systemScope.getIcon())
                .isDefault(systemScope.isDefaultScope())
                .isRestricted(systemScope.isRestricted())
                .build();
    }
}
