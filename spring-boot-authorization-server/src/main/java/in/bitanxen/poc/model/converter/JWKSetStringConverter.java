package in.bitanxen.poc.model.converter;

import com.nimbusds.jose.jwk.JWKSet;
import lombok.extern.log4j.Log4j2;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;
import java.text.ParseException;

@Converter
@Log4j2
public class JWKSetStringConverter implements AttributeConverter<JWKSet, String> {

    @Override
    public String convertToDatabaseColumn(JWKSet attribute) {
        if (attribute == null) {
            return null;
        }
        return attribute.toString();
    }

    @Override
    public JWKSet convertToEntityAttribute(String dbData) {
        if(dbData == null) {
            return null;
        }
        try {
            return JWKSet.parse(dbData);
        } catch (ParseException e) {
            log.error("Unable to parse JWK Set", e);
            return null;
        }
    }
}
