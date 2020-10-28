package in.bitanxen.poc.model.converter;

import com.nimbusds.jose.JWSAlgorithm;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

@Converter
public class JWSAlgorithmStringConverter implements AttributeConverter<JWSAlgorithm, String> {

    @Override
    public String convertToDatabaseColumn(JWSAlgorithm attribute) {
        if(attribute == null) {
            return null;
        }
        return attribute.getName();
    }

    @Override
    public JWSAlgorithm convertToEntityAttribute(String dbData) {
        if (dbData == null) {
            return null;
        }
        return JWSAlgorithm.parse(dbData);
    }
}
