package in.bitanxen.poc.model.converter;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

@Converter
public class SimpleGrantedAuthorityStringConverter implements AttributeConverter<SimpleGrantedAuthority, String> {

    @Override
    public String convertToDatabaseColumn(SimpleGrantedAuthority attribute) {
        if (attribute == null) {
            return null;
        }
        return attribute.getAuthority();
    }

    @Override
    public SimpleGrantedAuthority convertToEntityAttribute(String dbData) {
        if (dbData == null) {
            return null;
        }
        return new SimpleGrantedAuthority(dbData);
    }
}
