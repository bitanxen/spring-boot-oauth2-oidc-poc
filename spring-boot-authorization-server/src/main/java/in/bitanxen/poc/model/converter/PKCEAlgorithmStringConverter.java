package in.bitanxen.poc.model.converter;

import in.bitanxen.poc.config.jose.PKCEAlgorithm;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

@Converter
public class PKCEAlgorithmStringConverter implements AttributeConverter<PKCEAlgorithm, String> {

    @Override
    public String convertToDatabaseColumn(PKCEAlgorithm attribute) {
        if (attribute == null) {
            return null;
        }
        return attribute.getName();
    }

    /* (non-Javadoc)
     * @see javax.persistence.AttributeConverter#convertToEntityAttribute(java.lang.Object)
     */
    @Override
    public PKCEAlgorithm convertToEntityAttribute(String dbData) {
        if (dbData == null) {
            return null;
        }
        return PKCEAlgorithm.parse(dbData);
    }
}
