package in.bitanxen.poc.model.converter;

import com.nimbusds.jose.JWEAlgorithm;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

@Converter
public class JWEAlgorithmStringConverter implements AttributeConverter<JWEAlgorithm, String> {

    @Override
    public String convertToDatabaseColumn(JWEAlgorithm attribute) {
        if (attribute == null) {
            return null;
        }
        return attribute.getName();
    }

    @Override
    public JWEAlgorithm convertToEntityAttribute(String dbData) {
        if (dbData == null) {
            return null;
        }
        return JWEAlgorithm.parse(dbData);
    }
}
